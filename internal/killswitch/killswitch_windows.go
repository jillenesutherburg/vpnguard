//go:build windows

// Package killswitch implements a fail-closed firewall on top of the
// Windows Filtering Platform (WFP).
//
// Design:
//   - We register our own persistent Provider and a Sublayer with maximum
//     weight, so our verdicts win over rules from other software.
//   - All rules are Persistent: if this process crashes or the service is
//     killed, the block stays in the kernel (fail-closed). Rules are only
//     removed by an explicit Disable()/Panic().
//   - Default verdict is BLOCK (weight 0, no conditions). Everything else
//     is a narrow PERMIT with higher weight.
package killswitch

import (
	"fmt"
	"log"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"unsafe"

	"github.com/tailscale/wf"
	"golang.org/x/sys/windows"
)

// Endpoint is a VPN server endpoint that must stay reachable outside the
// tunnel so that OpenVPN can (re)connect.
type Endpoint struct {
	Addr  netip.Addr
	Port  uint16
	Proto wf.IPProto // wf.IPProtoUDP or wf.IPProtoTCP
}

// Config is the desired firewall state.
type Config struct {
	// AllowLAN permits traffic to RFC1918 / link-local / multicast ranges.
	AllowLAN bool

	// DNSWhenDown controls port-53 access while NO tunnel is up, so that
	// OpenVPN can resolve `remote` hostnames (Windows resolves DNS from
	// svchost.exe — the DNS Client service — so an openvpn.exe app-id
	// rule can never match DNS traffic):
	//   "off"     — no DNS at all; reconnect relies on the resolve cache
	//   "svchost" — port 53 only for the DNS Client service (default)
	//   "all"     — port 53 for everything (widest, старый режим коллеги)
	DNSWhenDown string

	// VPNEndpoints are the only remote destinations reachable outside the
	// tunnel (besides infrastructure like DHCP).
	VPNEndpoints []Endpoint

	// VPNBinary, if set, restricts the endpoint + DNS escape hatch to this
	// executable only (e.g. openvpn.exe). Strongly recommended.
	VPNBinary string

	// LockEndpointToApp: when true AND VPNBinary is set, the permit rule for
	// the VPN server is additionally restricted to VPNBinary via app-id.
	// Default false: the server permit is IP:port/proto only. This matters
	// because the process that actually connects to the server may differ
	// from VPNBinary (OpenVPN installed as a service, GUI+service mode,
	// child processes) — an app-id mismatch there silently blocks the
	// reconnect. The permit is already narrow (single server IP + port), so
	// dropping the app-id condition is a safe default that "just connects".
	LockEndpointToApp bool

	// TunnelLUIDs are interface LUIDs of active VPN tunnel adapters.
	// Traffic on these interfaces is permitted.
	TunnelLUIDs []uint64

	// AppPolicy: "all" permits any app through the tunnel; "allowlist"
	// permits only AllowedApps (each restricted to the tunnel interface).
	AppPolicy string

	// AllowedApps are absolute paths to executables allowed to use the
	// network (through the tunnel) when AppPolicy == "allowlist".
	AllowedApps []string
}

type Manager struct {
	session    *wf.Session
	persistent bool
}

// New opens a WFP session.
//
// persistent=false ("мягкий" режим): dynamic session — every rule is
// removed by the OS automatically when this process exits or crashes.
// No way to brick the machine; use while настраиваешься.
//
// persistent=true ("железный" режим): rules are marked PERSISTENT and
// survive service crash, kill and reboot; removed only by an explicit
// Disable()/panic. Fail-closed.
func New(persistent bool) (*Manager, error) {
	s, err := wf.New(&wf.Options{
		Name:        "VPNGuard",
		Description: "VPNGuard kill switch session",
		Dynamic:     !persistent,
	})
	if err != nil {
		return nil, fmt.Errorf("open WFP session (need admin rights): %w", err)
	}
	return &Manager{session: s, persistent: persistent}, nil
}

func (m *Manager) Close() error { return m.session.Close() }

// Apply brings WFP to the desired state with no fail-open window:
// new rules (including duplicate blocks) are added first, old rules are
// deleted after. Safe to call repeatedly; used for both initial enable
// and reconfiguration (e.g. tunnel adapter appeared/disappeared).
func (m *Manager) Apply(cfg *Config) error {
	log.Printf("killswitch: Apply начат — persistent=%v allowLan=%v dnsWhenDown=%s appPolicy=%s tunnelLUIDs=%v endpoints=%d allowedApps=%d",
		m.persistent, cfg.AllowLAN, cfg.DNSWhenDown, cfg.AppPolicy, cfg.TunnelLUIDs, len(cfg.VPNEndpoints), len(cfg.AllowedApps))
	for i, ep := range cfg.VPNEndpoints {
		log.Printf("killswitch:   endpoint[%d] = %s:%d/%v (сервер VPN, разрешён вне туннеля)", i, ep.Addr, ep.Port, protoName(ep.Proto))
	}
	if cfg.VPNBinary != "" {
		log.Printf("killswitch:   VPN-клиент (app-id): %s", cfg.VPNBinary)
	}

	if err := m.ensureFoundation(); err != nil {
		return err
	}
	oldIDs, err := m.ourRuleIDs()
	if err != nil {
		return err
	}
	log.Printf("killswitch: существующих наших правил в WFP: %d (будут заменены)", len(oldIDs))

	rules, err := buildRules(cfg, m.persistent)
	if err != nil {
		return err
	}
	log.Printf("killswitch: сгенерировано правил: %d — добавляю (make-before-break)", len(rules))
	for _, r := range rules {
		if err := m.session.AddRule(r); err != nil {
			return fmt.Errorf("add rule %q: %w", r.Name, err)
		}
		log.Printf("killswitch:   + %s", ruleSummary(r))
	}
	for _, id := range oldIDs {
		if err := m.session.DeleteRule(id); err != nil {
			return fmt.Errorf("delete stale rule: %w", err)
		}
	}
	log.Printf("killswitch: удалено старых правил: %d. Apply завершён, активно правил: %d",
		len(oldIDs), len(rules))
	return nil
}

// Disable removes every WFP object we own. Also used by `vpnguard panic`.
func (m *Manager) Disable() error {
	ids, err := m.ourRuleIDs()
	if err != nil {
		return err
	}
	log.Printf("killswitch: Disable/panic — снимаю %d правил + sublayer + provider (сеть будет открыта)", len(ids))
	var firstErr error
	for _, id := range ids {
		if err := m.session.DeleteRule(id); err != nil && firstErr == nil {
			firstErr = err
		}
	}
	if err := m.session.DeleteSublayer(sublayerID); err != nil && !isNotFound(err) && firstErr == nil {
		firstErr = err
	}
	if err := m.session.DeleteProvider(providerID); err != nil && !isNotFound(err) && firstErr == nil {
		firstErr = err
	}
	if firstErr != nil {
		log.Printf("killswitch: Disable завершён с ошибкой: %v", firstErr)
	} else {
		log.Printf("killswitch: Disable завершён, все объекты VPNGuard сняты")
	}
	return firstErr
}

// ActiveRuleCount reports how many of our rules are currently installed.
// 0 means the kill switch is disabled.
func (m *Manager) ActiveRuleCount() (int, error) {
	ids, err := m.ourRuleIDs()
	if err != nil {
		return 0, err
	}
	return len(ids), nil
}

func (m *Manager) ensureFoundation() error {
	provs, err := m.session.Providers()
	if err != nil {
		return err
	}
	haveProv := false
	for _, p := range provs {
		if p.ID == providerID {
			haveProv = true
			break
		}
	}
	if !haveProv {
		log.Printf("killswitch: создаю Provider VPNGuard (первый запуск)")
		if err := m.session.AddProvider(&wf.Provider{
			ID:          providerID,
			Name:        "VPNGuard",
			Description: "VPNGuard kill switch",
			Persistent:  true,
		}); err != nil {
			return fmt.Errorf("add provider: %w", err)
		}
	}
	subs, err := m.session.Sublayers(providerID)
	if err != nil {
		return err
	}
	if len(subs) == 0 {
		log.Printf("killswitch: создаю Sublayer (weight=0xFFFF, наши правила приоритетнее чужих)")
		if err := m.session.AddSublayer(&wf.Sublayer{
			ID:          sublayerID,
			Name:        "VPNGuard kill switch",
			Description: "Default-deny; narrow permits for VPN and infra",
			Persistent:  true,
			Provider:    providerID,
			Weight:      0xFFFF, // evaluated before everyone else
		}); err != nil {
			return fmt.Errorf("add sublayer: %w", err)
		}
	}
	return nil
}

func (m *Manager) ourRuleIDs() ([]wf.RuleID, error) {
	rules, err := m.session.Rules()
	if err != nil {
		return nil, err
	}
	var ids []wf.RuleID
	for _, r := range rules {
		if r.Provider == providerID {
			ids = append(ids, r.ID)
		}
	}
	return ids, nil
}

// ---- rule construction -----------------------------------------------

var (
	outLayers = []wf.LayerID{wf.LayerALEAuthConnectV4, wf.LayerALEAuthConnectV6}
	inLayers  = []wf.LayerID{wf.LayerALEAuthRecvAcceptV4, wf.LayerALEAuthRecvAcceptV6}
	allLayers = append(append([]wf.LayerID{}, outLayers...), inLayers...)

	lanV4 = []netip.Prefix{
		netip.MustParsePrefix("10.0.0.0/8"),
		netip.MustParsePrefix("172.16.0.0/12"),
		netip.MustParsePrefix("192.168.0.0/16"),
		netip.MustParsePrefix("169.254.0.0/16"),
		netip.MustParsePrefix("224.0.0.0/4"),
		netip.MustParsePrefix("255.255.255.255/32"),
	}
	linkLocalV6 = netip.MustParsePrefix("fe80::/10")
	multicastV6 = netip.MustParsePrefix("ff02::/16")
)

const (
	weightBlock  uint64 = 0
	weightPermit uint64 = 100
)

func buildRules(cfg *Config, persistent bool) ([]*wf.Rule, error) {
	var rules []*wf.Rule
	add := func(name string, layer wf.LayerID, action wf.Action, weight uint64, conds ...*wf.Match) {
		rules = append(rules, &wf.Rule{
			ID:         newRuleID(),
			Name:       "VPNGuard: " + name,
			Layer:      layer,
			Sublayer:   sublayerID,
			Weight:     weight,
			Conditions: conds,
			Action:     action,
			Persistent: persistent,
			Provider:   providerID,
		})
	}

	// 1. Default deny, inbound and outbound, v4 and v6.
	for _, l := range allLayers {
		add("block all", l, wf.ActionBlock, weightBlock)
	}

	// 2. Loopback.
	for _, l := range allLayers {
		add("permit loopback", l, wf.ActionPermit, weightPermit,
			&wf.Match{Field: wf.FieldFlags, Op: wf.MatchTypeFlagsAllSet, Value: wf.ConditionFlagIsLoopback})
	}

	// 3. DHCP (v4: client 68 -> server 67; v6: client 546 -> server 547).
	add("permit DHCPv4 out", wf.LayerALEAuthConnectV4, wf.ActionPermit, weightPermit,
		&wf.Match{Field: wf.FieldIPProtocol, Op: wf.MatchTypeEqual, Value: wf.IPProtoUDP},
		&wf.Match{Field: wf.FieldIPLocalPort, Op: wf.MatchTypeEqual, Value: uint16(68)},
		&wf.Match{Field: wf.FieldIPRemotePort, Op: wf.MatchTypeEqual, Value: uint16(67)})
	add("permit DHCPv4 in", wf.LayerALEAuthRecvAcceptV4, wf.ActionPermit, weightPermit,
		&wf.Match{Field: wf.FieldIPProtocol, Op: wf.MatchTypeEqual, Value: wf.IPProtoUDP},
		&wf.Match{Field: wf.FieldIPLocalPort, Op: wf.MatchTypeEqual, Value: uint16(68)})
	add("permit DHCPv6 out", wf.LayerALEAuthConnectV6, wf.ActionPermit, weightPermit,
		&wf.Match{Field: wf.FieldIPProtocol, Op: wf.MatchTypeEqual, Value: wf.IPProtoUDP},
		&wf.Match{Field: wf.FieldIPLocalPort, Op: wf.MatchTypeEqual, Value: uint16(546)},
		&wf.Match{Field: wf.FieldIPRemotePort, Op: wf.MatchTypeEqual, Value: uint16(547)})
	add("permit DHCPv6 in", wf.LayerALEAuthRecvAcceptV6, wf.ActionPermit, weightPermit,
		&wf.Match{Field: wf.FieldIPProtocol, Op: wf.MatchTypeEqual, Value: wf.IPProtoUDP},
		&wf.Match{Field: wf.FieldIPLocalPort, Op: wf.MatchTypeEqual, Value: uint16(546)})

	// 4. ICMPv6 NDP / RA on link-local and multicast (v6 won't work without it).
	for _, pfx := range []netip.Prefix{linkLocalV6, multicastV6} {
		add("permit NDP out", wf.LayerALEAuthConnectV6, wf.ActionPermit, weightPermit,
			&wf.Match{Field: wf.FieldIPProtocol, Op: wf.MatchTypeEqual, Value: wf.IPProtoICMPV6},
			&wf.Match{Field: wf.FieldIPRemoteAddress, Op: wf.MatchTypePrefix, Value: pfx})
	}
	add("permit NDP in", wf.LayerALEAuthRecvAcceptV6, wf.ActionPermit, weightPermit,
		&wf.Match{Field: wf.FieldIPProtocol, Op: wf.MatchTypeEqual, Value: wf.IPProtoICMPV6},
		&wf.Match{Field: wf.FieldIPRemoteAddress, Op: wf.MatchTypePrefix, Value: linkLocalV6})

	// 5. VPN server endpoints — the reconnect lifeline. Restricted to the
	// VPN binary when configured.
	// NOTE(first-build): verify wf.AppID's exact signature/return type
	// against the fetched tailscale/wf version; the WFP app ID is a
	// UTF-16LE NT-path blob under the hood and the wrapper type may differ.
	var vpnAppID string
	if cfg.VPNBinary != "" {
		id, err := wf.AppID(cfg.VPNBinary)
		if err != nil {
			return nil, fmt.Errorf("resolve AppID for %q: %w", cfg.VPNBinary, err)
		}
		vpnAppID = id
	}
	for _, ep := range cfg.VPNEndpoints {
		layer := wf.LayerALEAuthConnectV4
		if ep.Addr.Is6() {
			layer = wf.LayerALEAuthConnectV6
		}
		conds := []*wf.Match{
			{Field: wf.FieldIPProtocol, Op: wf.MatchTypeEqual, Value: ep.Proto},
			{Field: wf.FieldIPRemoteAddress, Op: wf.MatchTypeEqual, Value: ep.Addr},
			{Field: wf.FieldIPRemotePort, Op: wf.MatchTypeEqual, Value: ep.Port},
		}
		if vpnAppID != "" && cfg.LockEndpointToApp {
			conds = append(conds, &wf.Match{Field: wf.FieldALEAppID, Op: wf.MatchTypeEqual, Value: vpnAppID})
			log.Printf("killswitch:   (endpoint %s привязан к app-id %s)", ep.Addr, cfg.VPNBinary)
		}
		add("permit VPN endpoint "+ep.Addr.String(), layer, wf.ActionPermit, weightPermit, conds...)
	}

	// 6. DNS while the VPN is DOWN, so OpenVPN can re-resolve `remote`
	// hostnames. An app-id rule for openvpn.exe would be dead weight here:
	// Windows resolves DNS from svchost.exe (DNS Client service), not from
	// the requesting process — credit to the C# review for catching this.
	// The resolve cache makes "off" viable; "svchost" is the narrow default.
	if len(cfg.TunnelLUIDs) == 0 {
		switch cfg.DNSWhenDown {
		case "off":
			// nothing: reconnect uses cached endpoint IPs
		case "all":
			for _, proto := range []wf.IPProto{wf.IPProtoUDP, wf.IPProtoTCP} {
				for _, l := range outLayers {
					add("permit DNS (vpn down, all)", l, wf.ActionPermit, weightPermit,
						&wf.Match{Field: wf.FieldIPProtocol, Op: wf.MatchTypeEqual, Value: proto},
						&wf.Match{Field: wf.FieldIPRemotePort, Op: wf.MatchTypeEqual, Value: uint16(53)})
				}
			}
		default: // "svchost"
			sysRoot := os.Getenv("SystemRoot")
			if sysRoot == "" {
				sysRoot = `C:\Windows`
			}
			svchostID, err := wf.AppID(filepath.Join(sysRoot, "System32", "svchost.exe"))
			if err != nil {
				return nil, fmt.Errorf("resolve AppID for svchost: %w", err)
			}
			for _, proto := range []wf.IPProto{wf.IPProtoUDP, wf.IPProtoTCP} {
				for _, l := range outLayers {
					add("permit DNS (vpn down, svchost)", l, wf.ActionPermit, weightPermit,
						&wf.Match{Field: wf.FieldIPProtocol, Op: wf.MatchTypeEqual, Value: proto},
						&wf.Match{Field: wf.FieldIPRemotePort, Op: wf.MatchTypeEqual, Value: uint16(53)},
						&wf.Match{Field: wf.FieldALEAppID, Op: wf.MatchTypeEqual, Value: svchostID})
				}
			}
		}
	}

	// 7. Tunnel interfaces.
	for _, luid := range cfg.TunnelLUIDs {
		if cfg.AppPolicy == "allowlist" {
			// Outbound: only whitelisted apps, and only via the tunnel.
			for _, app := range cfg.AllowedApps {
				appID, err := wf.AppID(app)
				if err != nil {
					return nil, fmt.Errorf("resolve AppID for %q: %w", app, err)
				}
				for _, l := range outLayers {
					add("permit app via tunnel: "+app, l, wf.ActionPermit, weightPermit,
						&wf.Match{Field: wf.FieldIPLocalInterface, Op: wf.MatchTypeEqual, Value: luid},
						&wf.Match{Field: wf.FieldALEAppID, Op: wf.MatchTypeEqual, Value: appID})
				}
			}
			// DNS via the tunnel for ANY app: name resolution happens in
			// svchost.exe, not in the whitelisted app, so without this hole
			// allowlisted apps could never resolve hostnames.
			for _, proto := range []wf.IPProto{wf.IPProtoUDP, wf.IPProtoTCP} {
				for _, l := range outLayers {
					add("permit DNS via tunnel", l, wf.ActionPermit, weightPermit,
						&wf.Match{Field: wf.FieldIPLocalInterface, Op: wf.MatchTypeEqual, Value: luid},
						&wf.Match{Field: wf.FieldIPProtocol, Op: wf.MatchTypeEqual, Value: proto},
						&wf.Match{Field: wf.FieldIPRemotePort, Op: wf.MatchTypeEqual, Value: uint16(53)})
				}
			}
			// The VPN binary itself may also need the tunnel (e.g. keepalive).
			if vpnAppID != "" {
				for _, l := range outLayers {
					add("permit VPN binary via tunnel", l, wf.ActionPermit, weightPermit,
						&wf.Match{Field: wf.FieldIPLocalInterface, Op: wf.MatchTypeEqual, Value: luid},
						&wf.Match{Field: wf.FieldALEAppID, Op: wf.MatchTypeEqual, Value: vpnAppID})
				}
			}
		} else {
			for _, l := range outLayers {
				add("permit tunnel out", l, wf.ActionPermit, weightPermit,
					&wf.Match{Field: wf.FieldIPLocalInterface, Op: wf.MatchTypeEqual, Value: luid})
			}
		}
		// Inbound over the tunnel (needed for reverse tunnels / p2p).
		for _, l := range inLayers {
			add("permit tunnel in", l, wf.ActionPermit, weightPermit,
				&wf.Match{Field: wf.FieldIPLocalInterface, Op: wf.MatchTypeEqual, Value: luid})
		}
	}

	// 8. Optional LAN.
	if cfg.AllowLAN {
		for _, pfx := range lanV4 {
			add("permit LAN out "+pfx.String(), wf.LayerALEAuthConnectV4, wf.ActionPermit, weightPermit,
				&wf.Match{Field: wf.FieldIPRemoteAddress, Op: wf.MatchTypePrefix, Value: pfx})
			add("permit LAN in "+pfx.String(), wf.LayerALEAuthRecvAcceptV4, wf.ActionPermit, weightPermit,
				&wf.Match{Field: wf.FieldIPRemoteAddress, Op: wf.MatchTypePrefix, Value: pfx})
		}
	}

	return rules, nil
}

func isNotFound(err error) bool {
	return err != nil && strings.Contains(strings.ToLower(err.Error()), "not found")
}

// ---- tunnel adapter discovery ----------------------------------------

var (
	modiphlpapi                     = windows.NewLazySystemDLL("iphlpapi.dll")
	procConvertInterfaceIndexToLuid = modiphlpapi.NewProc("ConvertInterfaceIndexToLuid")
)

func luidFromIndex(index uint32) (uint64, error) {
	var luid uint64
	r, _, _ := procConvertInterfaceIndexToLuid.Call(uintptr(index), uintptr(unsafe.Pointer(&luid)))
	if r != 0 {
		return 0, fmt.Errorf("ConvertInterfaceIndexToLuid failed: 0x%x", r)
	}
	return luid, nil
}

// Adapter describes an up tunnel adapter (for WFP rules and tray status).
type Adapter struct {
	LUID uint64
	Name string
	IP   string
}

// FindTunnelAdapters returns up (operational) interfaces whose friendly
// name contains any of the given case-insensitive substrings, e.g.
// ["OpenVPN", "TAP", "Wintun"].
func FindTunnelAdapters(namePatterns []string) ([]Adapter, error) {
	ifaces, err := net.Interfaces()
	if err != nil {
		return nil, err
	}
	var out []Adapter
	for _, ifc := range ifaces {
		if ifc.Flags&net.FlagUp == 0 {
			continue
		}
		name := strings.ToLower(ifc.Name)
		matched := false
		for _, p := range namePatterns {
			if strings.Contains(name, strings.ToLower(p)) {
				matched = true
				break
			}
		}
		if !matched {
			continue
		}
		luid, err := luidFromIndex(uint32(ifc.Index))
		if err != nil {
			return nil, err
		}
		a := Adapter{LUID: luid, Name: ifc.Name}
		if addrs, err := ifc.Addrs(); err == nil {
			for _, addr := range addrs {
				if ipn, ok := addr.(*net.IPNet); ok && ipn.IP.To4() != nil {
					a.IP = ipn.IP.String()
					break
				}
			}
		}
		out = append(out, a)
	}
	return out, nil
}

// FindTunnelLUIDs is a convenience wrapper over FindTunnelAdapters.
func FindTunnelLUIDs(namePatterns []string) ([]uint64, error) {
	adapters, err := FindTunnelAdapters(namePatterns)
	if err != nil {
		return nil, err
	}
	var luids []uint64
	for _, a := range adapters {
		luids = append(luids, a.LUID)
	}
	return luids, nil
}

// ListInterfaces is a helper for the `vpnguard interfaces` command.
func ListInterfaces() (string, error) {
	ifaces, err := net.Interfaces()
	if err != nil {
		return "", err
	}
	var b strings.Builder
	for _, ifc := range ifaces {
		luid, err := luidFromIndex(uint32(ifc.Index))
		if err != nil {
			continue
		}
		state := "down"
		if ifc.Flags&net.FlagUp != 0 {
			state = "up"
		}
		fmt.Fprintf(&b, "idx=%-3d luid=%-20d state=%-4s name=%q\n", ifc.Index, luid, state, ifc.Name)
	}
	return b.String(), nil
}

// ---- logging helpers ---------------------------------------------------

func protoName(p wf.IPProto) string {
	switch p {
	case wf.IPProtoTCP:
		return "tcp"
	case wf.IPProtoUDP:
		return "udp"
	default:
		return fmt.Sprintf("proto#%d", uint8(p))
	}
}

// ruleSummary renders a rule for the log: action + name + layer.
func ruleSummary(r *wf.Rule) string {
	action := "PERMIT"
	if r.Action == wf.ActionBlock {
		action = "BLOCK "
	}
	return fmt.Sprintf("%s w=%-3d %-24s [%s, conds=%d]",
		action, r.Weight, strings.TrimPrefix(r.Name, "VPNGuard: "),
		layerName(r.Layer), len(r.Conditions))
}

func layerName(l wf.LayerID) string {
	switch l {
	case wf.LayerALEAuthConnectV4:
		return "out-v4"
	case wf.LayerALEAuthConnectV6:
		return "out-v6"
	case wf.LayerALEAuthRecvAcceptV4:
		return "in-v4"
	case wf.LayerALEAuthRecvAcceptV6:
		return "in-v6"
	default:
		return "layer?"
	}
}
