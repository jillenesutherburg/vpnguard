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
	stop := make(chan struct{})
	done := make(chan error, 1)
	go func() { done <- runLoop(stop) }()

	status <- svc.Status{State: svc.Running, Accepts: svc.AcceptStop | svc.AcceptShutdown}
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
				status <- svc.Status{State: svc.Stopped}
				return true, 1
			}
		}
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
	cfg, err := config.Load()
	if err != nil {
		return err
	}

	st := &svcState{cfg: cfg, tm: tunnels.NewManager(cfg.Tunnels)}
	defer func() { st.tm.StopAll() }()

	st.ks, err = killswitch.New(cfg.Killswitch.Persistent)
	if err != nil {
		return err
	}
	defer st.ks.Close()
	log.Printf("режим киллсвитча: persistent=%v (%s)", cfg.Killswitch.Persistent,
		map[bool]string{true: "железный", false: "мягкий: фильтры снимутся при остановке службы"}[cfg.Killswitch.Persistent])

	if cfg.Killswitch.Enabled {
		st.ksCfg, err = BuildKillswitchConfig(cfg, nil)
		if err != nil {
			return err
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

	<-stop
	cancel()
	<-done
	return nil
}

func (s *svcState) onVPNChange(st vpnmon.Status) {
	s.mu.Lock()
	defer s.mu.Unlock()
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
			return nil, err
		}
		eps = append(eps, ep)
	}
	return &killswitch.Config{
		AllowLAN:     cfg.Killswitch.AllowLAN,
		DNSWhenDown:  cfg.Killswitch.DNSWhenDown,
		VPNEndpoints: eps,
		VPNBinary:    cfg.OpenVPN.Binary,
		AppPolicy:    cfg.Killswitch.AppPolicy,
		AllowedApps:  cfg.Killswitch.AllowedApps,
	}, nil
}

func setupLog() {
	_ = os.MkdirAll(config.Dir, 0o755)
	// простая ротация: > 5 МБ — старый лог в .old, начинаем заново
	if fi, err := os.Stat(config.LogPath()); err == nil && fi.Size() > 5*1024*1024 {
		_ = os.Rename(config.LogPath(), config.LogPath()+".old")
	}
	f, err := os.OpenFile(config.LogPath(), os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o644)
	if err == nil {
		log.SetOutput(f)
	}
	log.SetFlags(log.LstdFlags | log.Lmsgprefix)
	log.SetPrefix("[vpnguard] ")
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
