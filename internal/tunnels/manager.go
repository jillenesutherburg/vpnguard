// Package tunnels supervises ssh tunnels and helper scripts: start after
// VPN is up, health-check them, restart with exponential backoff.
//
// Ported from the user's earlier VPNSentinel draft with two fixes:
//   - processes run inside a Windows Job Object (kill-on-close), so the
//     whole tree dies on restart, including orphans spawned by .bat files;
//   - restart delay grows exponentially up to a cap instead of hammering
//     a dead endpoint at a fixed interval.
package tunnels

import (
	"context"
	"fmt"
	"log"
	"net"
	"sync"
	"time"

	"github.com/YOURNAME/vpnguard/internal/config"
)

type State string

const (
	StateStopped    State = "остановлен"
	StateStarting   State = "запускается"
	StateRunning    State = "работает"
	StateUnhealthy  State = "проверка не проходит"
	StateRestarting State = "перезапуск"
	StateFailed     State = "ошибка запуска"
)

type TunnelStatus struct {
	Name     string
	State    State
	Restarts int
	Detail   string
}

const (
	maxBackoff = 60 * time.Second
	// A run longer than this is considered healthy: backoff resets.
	healthyRun = 60 * time.Second
)

type tunnel struct {
	cfg      config.Tunnel
	mu       sync.Mutex
	state    State
	restarts int
	detail   string
	cancel   context.CancelFunc
}

type Manager struct {
	mu      sync.Mutex
	tunnels map[string]*tunnel
	order   []string
	// OnUpdate is called (from supervisor goroutines) whenever any tunnel
	// changes state; used by the tray UI later.
	OnUpdate func()
}

func NewManager(cfgs []config.Tunnel) *Manager {
	m := &Manager{tunnels: map[string]*tunnel{}}
	for _, c := range cfgs {
		m.tunnels[c.Name] = &tunnel{cfg: c, state: StateStopped}
		m.order = append(m.order, c.Name)
	}
	return m
}

func (m *Manager) notify() {
	if m.OnUpdate != nil {
		m.OnUpdate()
	}
}

// StartAll starts every tunnel with autostart enabled. Called when the
// VPN comes up.
func (m *Manager) StartAll() {
	m.mu.Lock()
	defer m.mu.Unlock()
	for _, name := range m.order {
		t := m.tunnels[name]
		if t.cfg.AutoStartEnabled() {
			m.startLocked(t)
		}
	}
}

// StopAll stops every tunnel. Called when the VPN goes down (the kill
// switch would strangle them anyway; stopping avoids error-spam and lets
// them restart cleanly on reconnect).
func (m *Manager) StopAll() {
	m.mu.Lock()
	defer m.mu.Unlock()
	for _, t := range m.tunnels {
		m.stopLocked(t)
	}
}

func (m *Manager) Start(name string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if t, ok := m.tunnels[name]; ok {
		m.startLocked(t)
	}
}

func (m *Manager) Stop(name string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if t, ok := m.tunnels[name]; ok {
		m.stopLocked(t)
	}
}

func (m *Manager) Restart(name string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if t, ok := m.tunnels[name]; ok {
		m.stopLocked(t)
		m.startLocked(t)
	}
}

func (m *Manager) Statuses() []TunnelStatus {
	m.mu.Lock()
	defer m.mu.Unlock()
	out := make([]TunnelStatus, 0, len(m.order))
	for _, name := range m.order {
		t := m.tunnels[name]
		t.mu.Lock()
		out = append(out, TunnelStatus{Name: name, State: t.state, Restarts: t.restarts, Detail: t.detail})
		t.mu.Unlock()
	}
	return out
}

func (m *Manager) startLocked(t *tunnel) {
	t.mu.Lock()
	if t.cancel != nil { // already running
		t.mu.Unlock()
		return
	}
	ctx, cancel := context.WithCancel(context.Background())
	t.cancel = cancel
	t.restarts = 0
	t.mu.Unlock()
	go m.supervise(ctx, t)
}

func (m *Manager) stopLocked(t *tunnel) {
	t.mu.Lock()
	if t.cancel != nil {
		t.cancel()
		t.cancel = nil
	}
	t.mu.Unlock()
}

func (t *tunnel) setState(s State, detail string) {
	t.mu.Lock()
	t.state, t.detail = s, detail
	t.mu.Unlock()
}

func (m *Manager) supervise(ctx context.Context, t *tunnel) {
	defer func() {
		if r := recover(); r != nil {
			log.Printf("[%s] PANIC в supervise: %v", t.cfg.Name, r)
		}
		t.setState(StateStopped, "")
		m.notify()
	}()

	backoff := t.cfg.RestartDelay()
	for {
		t.setState(StateStarting, "")
		m.notify()
		log.Printf("[%s] запуск: %s", t.cfg.Name, t.cfg.Script)
		startedAt := time.Now()

		proc, err := startProcess(t.cfg.Script, t.cfg.Args)
		if err != nil {
			t.setState(StateFailed, err.Error())
			m.notify()
			log.Printf("[%s] ошибка запуска: %v", t.cfg.Name, err)
		} else {
			t.setState(StateRunning, "")
			m.notify()
			exited := make(chan error, 1)
			go func() { exited <- proc.Wait() }()
			m.watch(ctx, t, proc, exited)
		}

		select {
		case <-ctx.Done():
			return
		default:
		}

		// Backoff: reset after a healthy run, otherwise double up to cap.
		if time.Since(startedAt) >= healthyRun {
			backoff = t.cfg.RestartDelay()
		}
		t.mu.Lock()
		t.restarts++
		t.mu.Unlock()
		t.setState(StateRestarting, fmt.Sprintf("пауза %s", backoff))
		m.notify()
		log.Printf("[%s] перезапуск через %s", t.cfg.Name, backoff)
		select {
		case <-ctx.Done():
			return
		case <-time.After(backoff):
		}
		if backoff *= 2; backoff > maxBackoff {
			backoff = maxBackoff
		}
	}
}

func (m *Manager) watch(ctx context.Context, t *tunnel, proc *proc, exited <-chan error) {
	var checkC <-chan time.Time
	if c := t.cfg.Check; c != nil && c.Type == "tcp" {
		ticker := time.NewTicker(c.Interval())
		checkC = ticker.C
		defer ticker.Stop()
	}
	fails := 0
	for {
		select {
		case <-ctx.Done():
			proc.Kill()
			<-exited
			return
		case err := <-exited:
			log.Printf("[%s] процесс завершился: %v", t.cfg.Name, err)
			proc.Close()
			return
		case <-checkC:
			if tcpCheck(t.cfg.Check.Target, t.cfg.Check.Timeout()) {
				fails = 0
				t.setState(StateRunning, "")
				m.notify()
				continue
			}
			fails++
			t.setState(StateUnhealthy, fmt.Sprintf("провалов: %d/%d", fails, t.cfg.Check.Threshold()))
			m.notify()
			log.Printf("[%s] health-check fail %d/%d (%s)", t.cfg.Name, fails, t.cfg.Check.Threshold(), t.cfg.Check.Target)
			if fails >= t.cfg.Check.Threshold() {
				proc.Kill()
				<-exited
				proc.Close()
				return
			}
		}
	}
}

func tcpCheck(target string, timeout time.Duration) bool {
	conn, err := net.DialTimeout("tcp", target, timeout)
	if err != nil {
		return false
	}
	_ = conn.Close()
	return true
}
