//go:build windows

// Package vpnmon watches VPN state. The authoritative signal is the
// tunnel adapter being up (that is also what the kill switch keys on);
// the OpenVPN management interface, when configured, refines the status
// with CONNECTED/RECONNECTING detail and the assigned IP.
//
// Management polling is ported from the user's earlier VPNSentinel draft.
package vpnmon

import (
	"bufio"
	"cmp"
	"context"
	"fmt"
	"log"
	"net"
	"slices"
	"strings"
	"time"

	"github.com/YOURNAME/vpnguard/internal/config"
	"github.com/YOURNAME/vpnguard/internal/killswitch"
)

type Status struct {
	Connected bool
	Adapters  []killswitch.Adapter // tunnel adapters currently up
	Detail    string
}

func (s Status) LUIDs() []uint64 {
	out := make([]uint64, 0, len(s.Adapters))
	for _, a := range s.Adapters {
		out = append(out, a.LUID)
	}
	return out
}

func (s Status) Equal(o Status) bool {
	return s.Connected == o.Connected && slices.Equal(s.LUIDs(), o.LUIDs())
}

type Monitor struct {
	cfg      *config.File
	interval time.Duration
	// OnChange fires on every state transition, including the initial one.
	OnChange func(Status)
}

func New(cfg *config.File, onChange func(Status)) *Monitor {
	return &Monitor{cfg: cfg, interval: 2 * time.Second, OnChange: onChange}
}

func (m *Monitor) Run(ctx context.Context) {
	log.Printf("монитор VPN запущен (management=%q, patterns=%v)",
		m.cfg.OpenVPN.Management, m.cfg.Killswitch.TunnelInterfaces)
	var last *Status
	t := time.NewTicker(m.interval)
	defer t.Stop()
	for {
		st := m.poll()
		if last == nil || !st.Equal(*last) {
			last = &st
			log.Printf("VPN: connected=%v adapters=%v %s", st.Connected, st.Adapters, st.Detail)
			if m.OnChange != nil {
				m.OnChange(st)
			}
		}
		select {
		case <-ctx.Done():
			log.Printf("монитор VPN остановлен")
			return
		case <-t.C:
		}
	}
}

func (m *Monitor) poll() Status {
	adapters, err := killswitch.FindTunnelAdapters(m.cfg.Killswitch.TunnelInterfaces)
	if err != nil {
		return Status{Connected: false, Detail: "ошибка перечисления адаптеров: " + err.Error()}
	}
	slices.SortFunc(adapters, func(a, b killswitch.Adapter) int {
		return cmp.Compare(a.LUID, b.LUID)
	})
	st := Status{Connected: len(adapters) > 0, Adapters: adapters}

	// Management interface (optional) refines the picture: the adapter can
	// linger up for a moment while OpenVPN is already reconnecting.
	if m.cfg.OpenVPN.Management != "" {
		if mgmtConnected, detail, err := m.pollManagement(); err == nil {
			st.Detail = detail
			if !mgmtConnected {
				st.Connected = false
			}
		}
	}
	return st
}

// pollManagement asks the OpenVPN management interface for its state.
// Note: OpenVPN allows only ONE management client; OpenVPN GUI occupies
// it. Use this only when running OpenVPN yourself with a dedicated
// `management 127.0.0.1 <port>` line in the .ovpn. Adapter detection
// works fine without it.
func (m *Monitor) pollManagement() (bool, string, error) {
	conn, err := net.DialTimeout("tcp", m.cfg.OpenVPN.Management, 2*time.Second)
	if err != nil {
		return false, "", err
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(3 * time.Second))
	r := bufio.NewReader(conn)
	if pw := m.cfg.OpenVPN.ManagementPassword; pw != "" {
		peek, _ := r.Peek(14)
		if strings.HasPrefix(string(peek), "ENTER PASSWORD") {
			_, _ = r.ReadString(':')
			fmt.Fprintf(conn, "%s\n", pw)
			_, _ = r.ReadString('\n')
		}
	}
	fmt.Fprint(conn, "state\n")
	var stateLine string
	for {
		line, err := r.ReadString('\n')
		if err != nil {
			break
		}
		line = strings.TrimSpace(line)
		switch {
		case line == "END":
			goto done
		case strings.HasPrefix(line, ">"): // async notifications, skip
			continue
		case strings.Contains(line, ","):
			stateLine = line
		}
	}
done:
	if stateLine == "" {
		return false, "management: нет данных state", nil
	}
	parts := strings.Split(stateLine, ",")
	connected := len(parts) >= 2 && parts[1] == "CONNECTED"
	detail := "management: " + safeIdx(parts, 1)
	if connected && len(parts) >= 4 && parts[3] != "" {
		detail += ", IP " + parts[3]
	}
	return connected, detail, nil
}

func safeIdx(s []string, i int) string {
	if i < len(s) {
		return s[i]
	}
	return ""
}
