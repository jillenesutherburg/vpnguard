//go:build windows

// Package wsvc implements the VPNGuard Windows service.
//
// The service is intentionally boring: load config -> apply kill switch ->
// watch tunnel adapters -> re-apply on change. All firewall state is
// persistent in the WFP engine, so if this service dies the network stays
// locked down (fail-closed), and a restart simply reconciles state.
package wsvc

import (
	"context"
	"fmt"
	"io"
	"log"
	"os"
	"slices"
	"sync"
	"time"

	"github.com/YOURNAME/vpnguard/internal/config"
	"github.com/YOURNAME/vpnguard/internal/ipc"
	"github.com/YOURNAME/vpnguard/internal/killswitch"
	"github.com/YOURNAME/vpnguard/internal/tunnels"
	"github.com/YOURNAME/vpnguard/internal/vpnmon"
	"golang.org/x/sys/windows/svc"
	"golang.org/x/sys/windows/svc/eventlog"
	"golang.org/x/sys/windows/svc/mgr"
)

const Name = "VPNGuard"

// Run starts the service loop. If interactive is true it runs in the
// foreground (for debugging with `vpnguard service run`).
func Run(interactive bool) error {
	setupLog()
	if interactive {
		log.Printf("running interactively (debug)")
		return runLoop(make(chan struct{}))
	}
	return svc.Run(Name, &handler{})
}

type handler struct{}

func (h *handler) Execute(args []string, req <-chan svc.ChangeRequest, status chan<- svc.Status) (bool, uint32) {
	status <- svc.Status{State: svc.StartPending}

	// runLoop сигналит через started, что инициализация (конфиг, WFP,
	// первичное применение правил) прошла успешно. Только после этого
	// сообщаем SCM Running — иначе быстрое падение выглядит как
	// "запустилась и умерла", а трей стучится в несуществующий пайп.
	stop := make(chan struct{})
	done := make(chan error, 1)
	started := make(chan struct{})
	go func() { done <- runLoopSignaled(stop, started) }()

	select {
	case <-started:
		status <- svc.Status{State: svc.Running, Accepts: svc.AcceptStop | svc.AcceptShutdown}
	case err := <-done:
		// упали ДО успешного старта — громко и в лог, и в Event Log
		reportStartFailure(err)
		status <- svc.Status{State: svc.Stopped}
		return true, 1
	case <-time.After(60 * time.Second):
		reportStartFailure(fmt.Errorf("инициализация не завершилась за 60с"))
		close(stop)
		status <- svc.Status{State: svc.Stopped}
		return true, 1
	}

	for {
		select {
		case c := <-req:
			switch c.Cmd {
			case svc.Interrogate:
				status <- c.CurrentStatus
			case svc.Stop, svc.Shutdown:
				status <- svc.Status{State: svc.StopPending}
				close(stop)
				<-done
				// NOTE: we deliberately do NOT remove the WFP rules here.
				// Fail-closed means the block outlives the service.
				status <- svc.Status{State: svc.Stopped}
				return false, 0
			}
		case err := <-done:
			if err != nil {
				log.Printf("service loop failed: %v", err)
				reportStartFailure(err)
				status <- svc.Status{State: svc.Stopped}
				return true, 1
			}
		}
	}
}

// reportStartFailure дублирует критическую ошибку старта в Windows Event
// Log (журнал "Приложения", источник VPNGuard) — так причина видна даже
// если лог-файл не создался (нет прав/путь). Смотреть:
//   Get-EventLog -LogName Application -Source VPNGuard -Newest 5
func reportStartFailure(err error) {
	msg := fmt.Sprintf("VPNGuard: служба не смогла стартовать: %v", err)
	log.Print(msg)
	if el, e := eventlog.Open(Name); e == nil {
		_ = el.Error(1, msg)
		_ = el.Close()
	}
}

// svcState is everything the run loop and the IPC handler share.
type svcState struct {
	mu           sync.Mutex
	cfg          *config.File
	ks           *killswitch.Manager
	ksCfg        *killswitch.Config // nil when killswitch disabled
	tm           *tunnels.Manager
	last         vpnmon.Status
	wasConnected bool
	applied      bool
}

func runLoop(stop <-chan struct{}) error {
	return runLoopSignaled(stop, nil)
}

// runLoopSignaled закрывает started после того, как конфиг загружен, WFP-сессия
// открыта и (если киллсвитч включён) endpoints построены — то есть после точки,
// пройдя которую служба считается успешно стартовавшей. started может быть nil
// (интерактивный режим).
func runLoopSignaled(stop <-chan struct{}, started chan<- struct{}) error {
	log.Printf("runLoop: загружаю конфиг из %s", config.Path())
	cfg, err := config.Load()
	if err != nil {
		return fmt.Errorf("загрузка конфига %s: %w", config.Path(), err)
	}

	st := &svcState{cfg: cfg, tm: tunnels.NewManager(cfg.Tunnels)}
	defer func() { st.tm.StopAll() }()

	st.ks, err = killswitch.New(cfg.Killswitch.Persistent)
	if err != nil {
		return fmt.Errorf("открытие WFP-сессии (нужны права администратора): %w", err)
	}
	defer st.ks.Close()
	log.Printf("режим киллсвитча: persistent=%v (%s)", cfg.Killswitch.Persistent,
		map[bool]string{true: "железный", false: "мягкий: фильтры снимутся при остановке службы"}[cfg.Killswitch.Persistent])

	if cfg.Killswitch.Enabled {
		st.ksCfg, err = BuildKillswitchConfig(cfg, nil)
		if err != nil {
			return fmt.Errorf("построение правил киллсвитча: %w", err)
		}
	} else {
		log.Printf("kill switch отключён в конфиге; работаю только как супервизор туннелей")
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	go func() {
		if err := ipc.Serve(ctx, st.handleIPC); err != nil {
			log.Printf("IPC-сервер не поднялся: %v", err)
		}
	}()

	done := make(chan struct{})
	go func() {
		vpnmon.New(cfg, st.onVPNChange).Run(ctx)
		close(done)
	}()

	// Инициализация прошла — сигналим SCM, что старт успешен.
	log.Printf("runLoop: инициализация завершена, служба готова")
	if started != nil {
		close(started)
	}

	<-stop
	cancel()
	<-done
	return nil
}

func (s *svcState) onVPNChange(st vpnmon.Status) {
	s.mu.Lock()
	defer s.mu.Unlock()
	log.Printf("событие VPN: connected=%v adapters=%v luids=%v", st.Connected, st.Adapters, st.LUIDs())
	s.last = st
	s.reconcileLocked()
}

// reconcileLocked drives killswitch and tunnels to match s.last / s.cfg.
func (s *svcState) reconcileLocked() {
	st := s.last

	// 1. Kill switch follows the tunnel adapter set. Even with zero
	// adapters the block set must be in place (that IS the kill switch).
	if s.ksCfg != nil {
		s.ksCfg.TunnelLUIDs = st.LUIDs()
		if err := s.ks.Apply(s.ksCfg); err != nil {
			log.Printf("apply kill switch: %v", err)
		} else if !s.applied {
			s.applied = true
			log.Printf("kill switch применён")
		}
	}

	// 2. Tunnels are gated on VPN state.
	if st.Connected && !s.wasConnected {
		log.Printf("VPN поднялся — запускаю туннели")
		s.tm.StartAll()
	}
	if !st.Connected && s.wasConnected && s.cfg.StopOnVPNDown() {
		log.Printf("VPN упал — останавливаю туннели до восстановления")
		s.tm.StopAll()
	}
	s.wasConnected = st.Connected
}

// ---- IPC (протокол совместим с C#-треем VpnSentinel) -------------------

func (s *svcState) handleIPC(req ipc.Request) ipc.Response {
	s.mu.Lock()
	defer s.mu.Unlock()
	log.Printf("IPC команда: %s%s", req.Cmd, argSuffix(req.Arg))
	switch req.Cmd {
	case "ping":
		return ipc.Success("pong")

	case "status":
		return ipc.Success(s.statusLocked())

	case "enable":
		s.cfg.Killswitch.Enabled = true
		ksCfg, err := BuildKillswitchConfig(s.cfg, nil)
		if err != nil {
			return ipc.Fail(err.Error())
		}
		s.ksCfg = ksCfg
		s.applied = false
		s.reconcileLocked()
		return ipc.Success(s.statusLocked())

	case "disable":
		s.cfg.Killswitch.Enabled = false
		s.ksCfg = nil
		s.applied = false
		if err := s.ks.Disable(); err != nil {
			return ipc.Fail(err.Error())
		}
		log.Printf("киллсвитч выключен по команде из трея — сеть открыта")
		return ipc.Success(s.statusLocked())

	case "reload":
		fresh, err := config.Load()
		if err != nil {
			return ipc.Fail("конфиг не перечитан: " + err.Error())
		}
		s.cfg = fresh
		s.tm.StopAll()
		s.tm = tunnels.NewManager(fresh.Tunnels)
		s.ksCfg = nil
		s.applied = false
		if fresh.Killswitch.Enabled {
			ksCfg, err := BuildKillswitchConfig(fresh, nil)
			if err != nil {
				return ipc.Fail(err.Error())
			}
			s.ksCfg = ksCfg
		} else {
			if err := s.ks.Disable(); err != nil {
				log.Printf("disable при reload: %v", err)
			}
		}
		s.wasConnected = false // перезапустить туннели, если VPN уже поднят
		s.reconcileLocked()
		log.Printf("конфиг перечитан")
		return ipc.Success(s.statusLocked())

	default:
		return ipc.Fail("неизвестная команда: " + req.Cmd)
	}
}

func (s *svcState) statusLocked() ipc.ServiceStatus {
	out := ipc.ServiceStatus{
		KillswitchEnabled: s.ksCfg != nil,
		VpnConnected:      s.last.Connected,
		Persistent:        s.cfg.Killswitch.Persistent,
		WhitelistMode:     s.cfg.Killswitch.AppPolicy == "allowlist",
		DNSWhenDown:       s.cfg.Killswitch.DNSWhenDown,
		Scripts:           []ipc.ScriptStatus{},
	}
	if len(s.last.Adapters) > 0 {
		out.AdapterName = s.last.Adapters[0].Name
		out.AdapterIP = s.last.Adapters[0].IP
	}
	for _, t := range s.tm.Statuses() {
		out.Scripts = append(out.Scripts, ipc.ScriptStatus{
			Name:     t.Name,
			Running:  t.State == tunnels.StateRunning || t.State == tunnels.StateUnhealthy,
			Restarts: t.Restarts,
			State:    string(t.State),
			Detail:   t.Detail,
		})
	}
	return out
}

// BuildKillswitchConfig converts the YAML config into the killswitch
// runtime config. Extra endpoints (e.g. from CLI) can be injected.
func BuildKillswitchConfig(cfg *config.File, extra []killswitch.Endpoint) (*killswitch.Config, error) {
	log.Printf("build: парсю .ovpn: %s", cfg.OpenVPN.Config)
	remotes, err := config.ParseOVPN(cfg.OpenVPN.Config)
	if err != nil {
		return nil, fmt.Errorf("parse ovpn: %w", err)
	}
	resolved, err := config.Resolve(remotes)
	if err != nil {
		return nil, fmt.Errorf("resolve endpoints: %w", err)
	}
	eps := slices.Clone(extra)
	for _, r := range resolved {
		ep, err := killswitch.EndpointFrom(r.IP, r.Port, r.Proto)
		if err != nil {
			log.Printf("build: ПРОПУСКАЮ endpoint %s:%d/%s — %v", r.IP, r.Port, r.Proto, err)
			return nil, err
		}
		eps = append(eps, ep)
	}
	log.Printf("build: итоговых VPN-endpoints для permit-правил: %d (из них extra=%d)", len(eps), len(extra))
	if len(eps) == 0 {
		log.Printf("build: ВНИМАНИЕ! endpoints пуст — OpenVPN НЕ сможет подключиться при активном киллсвитче")
	}
	return &killswitch.Config{
		AllowLAN:          cfg.Killswitch.AllowLAN,
		DNSWhenDown:       cfg.Killswitch.DNSWhenDown,
		VPNEndpoints:      eps,
		VPNBinary:         cfg.OpenVPN.Binary,
		LockEndpointToApp: cfg.Killswitch.LockEndpointToApp,
		AppPolicy:         cfg.Killswitch.AppPolicy,
		AllowedApps:       cfg.Killswitch.AllowedApps,
	}, nil
}

func setupLog() {
	_ = os.MkdirAll(config.Dir, 0o755)
	// простая ротация: > 5 МБ — старый лог в .old, начинаем заново
	if fi, err := os.Stat(config.LogPath()); err == nil && fi.Size() > 5*1024*1024 {
		_ = os.Rename(config.LogPath(), config.LogPath()+".old")
	}
	log.SetFlags(log.LstdFlags | log.Lmsgprefix)
	log.SetPrefix("[vpnguard] ")

	f, err := os.OpenFile(config.LogPath(), os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o644)
	if err == nil {
		// пишем И в файл, И в stderr — чтобы `service run` показывал всё в консоли
		log.SetOutput(io.MultiWriter(f, os.Stderr))
	} else {
		log.SetOutput(os.Stderr)
		log.Printf("не смог открыть лог-файл %s: %v (пишу только в консоль)", config.LogPath(), err)
	}
	log.Printf("=== VPNGuard старт ===")
	log.Printf("рабочая директория (config/log/cache): %s", config.Dir)
	log.Printf("  причина выбора: %s", config.DirReason)
	log.Printf("конфиг: %s", config.Path())
	log.Printf("лог:    %s", config.LogPath())
	log.Printf("кэш:    %s", config.CachePath())
}

// ---- install / uninstall ----------------------------------------------

func Install() error {
	exe, err := os.Executable()
	if err != nil {
		return err
	}
	m, err := mgr.Connect()
	if err != nil {
		return fmt.Errorf("connect SCM (need admin): %w", err)
	}
	defer m.Disconnect()

	if s, err := m.OpenService(Name); err == nil {
		s.Close()
		return fmt.Errorf("service %s already installed", Name)
	}
	s, err := m.CreateService(Name, exe, mgr.Config{
		DisplayName: "VPNGuard kill switch",
		Description: "Fail-closed VPN kill switch and tunnel supervisor",
		StartType:   mgr.StartAutomatic,
		// Зависимости решают порядок старта:
		//  - BFE (Base Filtering Engine): без него WFP не работает вообще,
		//    поэтому наша служба обязана стартовать ПОСЛЕ него;
		//  - Tcpip: сеть должна существовать к моменту применения фильтров.
		// Windows гарантирует, что зависимости стартуют раньше нас.
		//
		// ВАЖНО про OpenVPN: сделать так, чтобы мы стартовали строго раньше
		// службы OpenVPN, зависимостью нельзя (это создаст обратную связь и
		// зависит от того, как именно у пользователя запущен OpenVPN). Окно
		// между загрузкой Windows и применением наших фильтров закрывается
		// НЕ порядком служб, а persistent-режимом: при persistent=true
		// фильтры уже лежат в ядре с прошлой сессии и блокируют трафик ещё
		// до старта нашей службы. Это и есть настоящий fail-closed на boot.
		Dependencies: []string{"BFE", "Tcpip"},
	}, "service", "run")
	if err != nil {
		return err
	}
	defer s.Close()

	// Auto-restart on crash: 5s, 10s, 30s; reset failure count daily.
	_ = s.SetRecoveryActions([]mgr.RecoveryAction{
		{Type: mgr.ServiceRestart, Delay: 5 * time.Second},
		{Type: mgr.ServiceRestart, Delay: 10 * time.Second},
		{Type: mgr.ServiceRestart, Delay: 30 * time.Second},
	}, 86400)

	return s.Start()
}

func Uninstall() error {
	m, err := mgr.Connect()
	if err != nil {
		return fmt.Errorf("connect SCM (need admin): %w", err)
	}
	defer m.Disconnect()
	s, err := m.OpenService(Name)
	if err != nil {
		return fmt.Errorf("service %s is not installed", Name)
	}
	defer s.Close()
	_, _ = s.Control(svc.Stop)
	time.Sleep(2 * time.Second)
	return s.Delete()
}

func argSuffix(arg string) string {
	if arg == "" {
		return ""
	}
	return " arg=" + arg
}

// Diagnose печатает полную картину для разбора проблем со стартом службы:
// какие пути используются, где реально лежит конфиг, установлена ли служба,
// её состояние и зарегистрированный путь exe, и хвост лога. Одна команда
// вместо ручного перебора PowerShell.
func Diagnose(w io.Writer) error {
	fmt.Fprintln(w, "===== VPNGuard диагностика =====")
	if exe, err := os.Executable(); err == nil {
		fmt.Fprintf(w, "exe:                 %s\n", exe)
	}
	fmt.Fprintf(w, "рабочая директория:  %s\n", config.Dir)
	fmt.Fprintf(w, "  причина выбора:    %s\n", config.DirReason)
	fmt.Fprintf(w, "конфиг:              %s\n", config.Path())
	if fi, err := os.Stat(config.Path()); err == nil {
		fmt.Fprintf(w, "  -> есть, %d байт, изменён %s\n", fi.Size(), fi.ModTime().Format("2006-01-02 15:04:05"))
	} else {
		fmt.Fprintf(w, "  -> НЕ НАЙДЕН (%v) — служба не стартует без конфига! Запусти: vpnguard init\n", err)
	}
	fmt.Fprintf(w, "лог:                 %s\n", config.LogPath())
	fmt.Fprintf(w, "кэш резолва:         %s\n", config.CachePath())

	// Состояние службы через SCM.
	fmt.Fprintln(w, "\n--- служба Windows ---")
	if m, err := mgr.Connect(); err == nil {
		defer m.Disconnect()
		if s, err := m.OpenService(Name); err == nil {
			defer s.Close()
			if st, err := s.Query(); err == nil {
				fmt.Fprintf(w, "состояние:           %s\n", svcStateName(st.State))
			}
			if cfg, err := s.Config(); err == nil {
				fmt.Fprintf(w, "зарегистрированный путь: %s\n", cfg.BinaryPathName)
				fmt.Fprintf(w, "тип запуска:         %s\n", startTypeName(cfg.StartType))
			}
		} else {
			fmt.Fprintf(w, "служба НЕ установлена (%v)\n", err)
			fmt.Fprintln(w, "  установить: vpnguard service install (от администратора)")
		}
	} else {
		fmt.Fprintf(w, "не удалось подключиться к SCM: %v (нужны права администратора)\n", err)
	}

	// Пробуем достучаться до IPC-пайпа — это ровно то, что делает трей.
	fmt.Fprintln(w, "\n--- IPC (то же, что проверяет трей) ---")
	fmt.Fprintf(w, "пайп:                %s\n", ipc.PipeName)
	// (само подключение проверяется треем; здесь только показываем имя)

	// Хвост лога.
	fmt.Fprintln(w, "\n--- последние строки лога ---")
	if data, err := os.ReadFile(config.LogPath()); err == nil {
		lines := splitTail(string(data), 30)
		for _, ln := range lines {
			fmt.Fprintln(w, ln)
		}
	} else {
		fmt.Fprintf(w, "лог не прочитан (%v)\n", err)
	}
	fmt.Fprintln(w, "\n================================")
	return nil
}

func svcStateName(s svc.State) string {
	switch s {
	case svc.Stopped:
		return "ОСТАНОВЛЕНА (Stopped) — упала или не запускалась"
	case svc.StartPending:
		return "запускается (StartPending)"
	case svc.StopPending:
		return "останавливается (StopPending)"
	case svc.Running:
		return "РАБОТАЕТ (Running)"
	default:
		return fmt.Sprintf("состояние #%d", s)
	}
}

func startTypeName(t uint32) string {
	switch t {
	case mgr.StartAutomatic:
		return "автоматически"
	case mgr.StartManual:
		return "вручную"
	case mgr.StartDisabled:
		return "отключена"
	default:
		return fmt.Sprintf("тип #%d", t)
	}
}

func splitTail(s string, n int) []string {
	var lines []string
	start := 0
	for i := 0; i < len(s); i++ {
		if s[i] == '\n' {
			lines = append(lines, trimCR(s[start:i]))
			start = i + 1
		}
	}
	if start < len(s) {
		lines = append(lines, trimCR(s[start:]))
	}
	if len(lines) > n {
		lines = lines[len(lines)-n:]
	}
	return lines
}

func trimCR(s string) string {
	if len(s) > 0 && s[len(s)-1] == '\r' {
		return s[:len(s)-1]
	}
	return s
}
