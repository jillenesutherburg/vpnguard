// Package config loads vpnguard configuration, parses OpenVPN client
// configs to extract server endpoints, and maintains a resolve cache so
// the kill switch can be rebuilt even when DNS is currently blocked.
package config

import (
	"bufio"
	"encoding/json"
	"fmt"
	"log"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"gopkg.in/yaml.v3"
)

// Dir is the state directory. Selection logic:
//  1. VPNGUARD_DIR env var wins (explicit override).
//  2. If the executable lives under Program Files / Windows (i.e. installed
//     by the setup, running as a service under LocalSystem), use
//     %ProgramData%\VPNGuard — a stable, predictable location that both the
//     service and the tray look at. This avoids the trap where a service
//     under Program Files silently writes config next to the exe while the
//     user edits a different file.
//  3. Otherwise (portable: exe on Desktop, USB stick, etc.) use the folder
//     next to the exe if writable, so config/log travel with the binary.
//  4. Fallback: %ProgramData%\VPNGuard.
var Dir, DirReason = resolveDir()

func resolveDir() (string, string) {
	programData := filepath.Join(os.Getenv("ProgramData"), "VPNGuard")

	if d := os.Getenv("VPNGUARD_DIR"); d != "" {
		return d, "переменная окружения VPNGUARD_DIR"
	}
	exe, err := os.Executable()
	if err != nil {
		return programData, "не удалось определить путь exe, использую ProgramData"
	}
	exeDir := filepath.Dir(exe)

	if inSystemLocation(exeDir) {
		return programData, "exe в системной папке (установлен) -> ProgramData"
	}
	if dirWritable(exeDir) {
		return exeDir, "портативный режим: папка рядом с exe"
	}
	return programData, "папка рядом с exe недоступна для записи -> ProgramData"
}

// inSystemLocation reports whether dir is under Program Files or Windows.
func inSystemLocation(dir string) bool {
	dir = strings.ToLower(filepath.Clean(dir))
	for _, env := range []string{"ProgramFiles", "ProgramFiles(x86)", "ProgramW6432", "SystemRoot", "windir"} {
		if base := os.Getenv(env); base != "" {
			base = strings.ToLower(filepath.Clean(base))
			if dir == base || strings.HasPrefix(dir, base+string(filepath.Separator)) {
				return true
			}
		}
	}
	return false
}

// dirWritable reports whether we can create files in dir (probe + cleanup).
func dirWritable(dir string) bool {
	probe := filepath.Join(dir, ".vpnguard-write-test")
	f, err := os.OpenFile(probe, os.O_CREATE|os.O_WRONLY, 0o644)
	if err != nil {
		return false
	}
	f.Close()
	os.Remove(probe)
	return true
}

func Path() string      { return filepath.Join(Dir, "config.yaml") }
func CachePath() string { return filepath.Join(Dir, "resolve-cache.json") }
func LogPath() string   { return filepath.Join(Dir, "vpnguard.log") }

type File struct {
	Killswitch Killswitch `yaml:"killswitch"`
	OpenVPN    OpenVPN    `yaml:"openvpn"`
	// StopTunnelsOnVPNDown: stop tunnel processes when VPN drops (they
	// would be strangled by the kill switch anyway); restart on reconnect.
	StopTunnelsOnVPNDown *bool    `yaml:"stop_tunnels_on_vpn_down"`
	Tunnels              []Tunnel `yaml:"tunnels"`
}

func (f *File) StopOnVPNDown() bool {
	return f.StopTunnelsOnVPNDown == nil || *f.StopTunnelsOnVPNDown
}

// Tunnel describes one supervised process (ssh tunnel, .bat script, ...).
// Field names match the older VPNSentinel config for easy migration.
type Tunnel struct {
	Name                string   `yaml:"name"`
	Script              string   `yaml:"script"` // .exe/.bat/.cmd path
	Args                []string `yaml:"args"`
	Autostart           *bool    `yaml:"autostart"`
	RestartDelaySeconds int      `yaml:"restart_delay_seconds"`
	Check               *Check   `yaml:"check"`
}

func (t Tunnel) AutoStartEnabled() bool { return t.Autostart == nil || *t.Autostart }

func (t Tunnel) RestartDelay() time.Duration {
	if t.RestartDelaySeconds <= 0 {
		return 5 * time.Second
	}
	return time.Duration(t.RestartDelaySeconds) * time.Second
}

// Check is a tunnel health check. type: "tcp" — a TCP connect to Target
// (e.g. the local forwarded port) must succeed.
type Check struct {
	Type            string `yaml:"type"`
	Target          string `yaml:"target"`
	IntervalSeconds int    `yaml:"interval_seconds"`
	TimeoutSeconds  int    `yaml:"timeout_seconds"`
	FailThreshold   int    `yaml:"fail_threshold"`
}

func (c Check) Interval() time.Duration {
	if c.IntervalSeconds <= 0 {
		return 15 * time.Second
	}
	return time.Duration(c.IntervalSeconds) * time.Second
}

func (c Check) Timeout() time.Duration {
	if c.TimeoutSeconds <= 0 {
		return 3 * time.Second
	}
	return time.Duration(c.TimeoutSeconds) * time.Second
}

func (c Check) Threshold() int {
	if c.FailThreshold <= 0 {
		return 2
	}
	return c.FailThreshold
}

type Killswitch struct {
	Enabled bool `yaml:"enabled"`
	// Persistent: false = "мягкий" режим (фильтры снимаются ОС при
	// остановке/падении службы — нельзя окирпичиться); true = "железный"
	// (фильтры переживают всё, снимать только `vpnguard disable/panic`).
	Persistent bool `yaml:"persistent"`
	// AllowLAN permits RFC1918 / link-local / multicast.
	AllowLAN bool `yaml:"allow_lan"`
	// DNSWhenDown: "svchost" (default) | "all" | "off" — port-53 policy
	// while no tunnel is up. See killswitch package docs.
	DNSWhenDown string `yaml:"dns_when_down"`
	// AppPolicy: "all" (default) or "allowlist".
	AppPolicy string `yaml:"app_policy"`
	// AllowedApps: absolute .exe paths, used when AppPolicy == allowlist.
	AllowedApps []string `yaml:"allowed_apps"`
	// LockEndpointToApp: restrict the VPN-server permit to openvpn.exe by
	// app-id. Default false — the permit is IP:port/proto only. Enable ONLY
	// if you are sure the exact binary path connects to the server; a
	// mismatch (OpenVPN-as-service, GUI+service, child process) silently
	// blocks reconnect. Leave false and the VPN just connects.
	LockEndpointToApp bool `yaml:"lock_endpoint_to_app"`
	// TunnelInterfaces: case-insensitive substrings matched against
	// adapter friendly names, e.g. ["OpenVPN", "TAP", "Wintun"].
	TunnelInterfaces []string `yaml:"tunnel_interfaces"`
}

type OpenVPN struct {
	// Config is the path to the .ovpn file; `remote`/`port`/`proto` are
	// parsed from it to derive the permitted endpoints.
	Config string `yaml:"config"`
	// Binary is the path to openvpn.exe; endpoint and DNS permits are
	// restricted to this executable.
	Binary string `yaml:"binary"`
	// Management is an optional "127.0.0.1:port" of the OpenVPN management
	// interface, for precise state detail. Leave empty when OpenVPN runs
	// under OpenVPN GUI (it occupies the single management slot).
	Management         string `yaml:"management"`
	ManagementPassword string `yaml:"management_password"`
}

func Load() (*File, error) {
	raw, err := os.ReadFile(Path())
	if err != nil {
		return nil, fmt.Errorf("read %s: %w", Path(), err)
	}
	var f File
	if err := yaml.Unmarshal(raw, &f); err != nil {
		return nil, fmt.Errorf("parse %s: %w", Path(), err)
	}
	if f.Killswitch.AppPolicy == "" {
		f.Killswitch.AppPolicy = "all"
	}
	if f.Killswitch.DNSWhenDown == "" {
		f.Killswitch.DNSWhenDown = "svchost"
	}
	if len(f.Killswitch.TunnelInterfaces) == 0 {
		f.Killswitch.TunnelInterfaces = []string{"OpenVPN", "TAP", "Wintun"}
	}
	return &f, nil
}

func WriteExample() error {
	if err := os.MkdirAll(Dir, 0o755); err != nil {
		return err
	}
	if _, err := os.Stat(Path()); err == nil {
		return fmt.Errorf("%s already exists, not overwriting", Path())
	}
	return os.WriteFile(Path(), []byte(exampleYAML), 0o644)
}

const exampleYAML = `killswitch:
  enabled: true
  # false = мягкий режим: фильтры автоматически снимаются при остановке
  # или падении службы (нельзя окирпичиться). Обкатайте систему в нём,
  # затем переключите в true — железный режим: фильтры переживают всё,
  # снимаются только командой vpnguard disable / panic.
  persistent: false
  allow_lan: true
  # Доступ к порту 53, пока VPN не подключён: svchost (DNS-служба Windows,
  # по умолчанию) | all (всем) | off (никому — реконнект по кэшу IP).
  dns_when_down: svchost
  app_policy: all            # all | allowlist
  allowed_apps: []           # used when app_policy: allowlist
  #  - 'C:\Windows\System32\OpenSSH\ssh.exe'
  # Привязывать разрешение к VPN-серверу к конкретному openvpn.exe (app-id).
  # false (по умолчанию) = разрешение по IP:порт:протокол сервера, без
  # привязки к процессу — так VPN подключается при любой схеме запуска
  # OpenVPN (служба, GUI+служба, дочерний процесс). true = строже, но при
  # несовпадении пути к exe реконнект будет молча заблокирован.
  lock_endpoint_to_app: false
  tunnel_interfaces: ["OpenVPN", "TAP", "Wintun"]

openvpn:
  config: 'C:\Program Files\OpenVPN\config\client.ovpn'
  binary: 'C:\Program Files\OpenVPN\bin\openvpn.exe'
  # Опционально: management-интерфейс OpenVPN для точного статуса.
  # НЕ включайте, если OpenVPN запускается через OpenVPN GUI — он сам
  # занимает единственный слот management. Определение по адаптеру
  # работает и без этого.
  # management: "127.0.0.1:25340"
  # management_password: ""

# Останавливать туннели при падении VPN и поднимать заново после
# восстановления (рекомендуется: true).
stop_tunnels_on_vpn_down: true

tunnels:
  # - name: "SOCKS proxy"
  #   script: 'C:\tunnels\socks.bat'   # .bat/.cmd/.exe
  #   # для ssh рекомендуются флаги:
  #   #   -o ServerAliveInterval=10 -o ServerAliveCountMax=3
  #   #   -o ExitOnForwardFailure=yes -N
  #   autostart: true
  #   restart_delay_seconds: 5         # стартовая пауза; растёт x2 до 60с
  #   check:
  #     type: tcp
  #     target: "127.0.0.1:1080"       # локальный проброшенный порт
  #     interval_seconds: 15
  #     timeout_seconds: 3
  #     fail_threshold: 2
`

// ---- .ovpn parsing -----------------------------------------------------

// RemoteSpec is one endpoint extracted from the .ovpn file, possibly with
// an unresolved hostname.
type RemoteSpec struct {
	Host  string
	Port  uint16
	Proto string // "udp" or "tcp"
}

// ParseOVPN extracts remote endpoints from an OpenVPN client config.
// Handles: `remote <host> [port] [proto]`, global `port`, global `proto`.
func ParseOVPN(path string) ([]RemoteSpec, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	defPort := uint16(1194)
	defProto := "udp"
	var remotes []RemoteSpec

	sc := bufio.NewScanner(f)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, "#") || strings.HasPrefix(line, ";") {
			continue
		}
		fields := strings.Fields(line)
		switch strings.ToLower(fields[0]) {
		case "port":
			if len(fields) >= 2 {
				if p, err := strconv.ParseUint(fields[1], 10, 16); err == nil {
					defPort = uint16(p)
					log.Printf("ovpn: global port = %d", defPort)
				} else {
					log.Printf("ovpn: WARNING bad `port %s`: %v", fields[1], err)
				}
			}
		case "proto":
			if len(fields) >= 2 {
				defProto = normProto(fields[1])
				log.Printf("ovpn: global proto = %s (from %q)", defProto, fields[1])
			}
		case "remote":
			if len(fields) >= 2 {
				r := RemoteSpec{Host: fields[1], Port: 0, Proto: ""}
				if len(fields) >= 3 {
					if p, err := strconv.ParseUint(fields[2], 10, 16); err == nil {
						r.Port = uint16(p)
					} else {
						log.Printf("ovpn: WARNING `remote %s` — port %q не распознан: %v (возьму порт по умолчанию)",
							r.Host, fields[2], err)
					}
				}
				if len(fields) >= 4 {
					r.Proto = normProto(fields[3])
				}
				log.Printf("ovpn: remote host=%s port=%d proto=%q (raw: %q)",
					r.Host, r.Port, r.Proto, line)
				remotes = append(remotes, r)
			} else {
				log.Printf("ovpn: WARNING строка `remote` без адреса: %q", line)
			}
		}
	}
	if err := sc.Err(); err != nil {
		return nil, err
	}
	for i := range remotes {
		if remotes[i].Port == 0 {
			remotes[i].Port = defPort
		}
		if remotes[i].Proto == "" {
			remotes[i].Proto = defProto
		}
	}
	if len(remotes) == 0 {
		return nil, fmt.Errorf("no `remote` directives found in %s", path)
	}
	log.Printf("ovpn: распознано endpoints: %d", len(remotes))
	return remotes, nil
}

func normProto(s string) string {
	s = strings.ToLower(s)
	if strings.HasPrefix(s, "tcp") {
		return "tcp"
	}
	return "udp"
}

// ---- resolve cache -----------------------------------------------------

// ResolvedEndpoint pairs an IP with port/proto, JSON-serializable.
type ResolvedEndpoint struct {
	IP    string `json:"ip"`
	Port  uint16 `json:"port"`
	Proto string `json:"proto"`
}

// Resolve turns RemoteSpecs into concrete IPs. On DNS failure it falls
// back to the cached result for that host (critical: when the kill switch
// is active and the service restarts, DNS is blocked — without the cache
// we could never rebuild the permit rules and would lock ourselves out).
func Resolve(remotes []RemoteSpec) ([]ResolvedEndpoint, error) {
	cache := loadCache()
	var out []ResolvedEndpoint
	seen := map[string]bool{}
	changed := false

	for _, r := range remotes {
		var ips []string
		var src string
		if addr, err := netip.ParseAddr(r.Host); err == nil {
			ips = []string{addr.String()}
			src = "IP напрямую"
		} else if resolved, err := net.LookupIP(r.Host); err == nil && len(resolved) > 0 {
			for _, ip := range resolved {
				ips = append(ips, ip.String())
			}
			cache[r.Host] = ips
			changed = true
			src = "DNS"
		} else if cached, ok := cache[r.Host]; ok {
			ips = cached
			src = "кэш"
		} else {
			log.Printf("resolve: НЕ УДАЛОСЬ разрешить %q и нет кэша: %v", r.Host, err)
			return nil, fmt.Errorf("cannot resolve %q and no cached IPs: %v", r.Host, err)
		}
		log.Printf("resolve: %s -> %v (%s), порт %d/%s", r.Host, ips, src, r.Port, r.Proto)
		for _, ip := range ips {
			key := ip + ":" + strconv.Itoa(int(r.Port)) + "/" + r.Proto
			if seen[key] {
				continue
			}
			seen[key] = true
			out = append(out, ResolvedEndpoint{IP: ip, Port: r.Port, Proto: r.Proto})
		}
	}
	if changed {
		saveCache(cache)
	}
	log.Printf("resolve: итоговых permit-endpoints для сервера: %d", len(out))
	return out, nil
}

func loadCache() map[string][]string {
	m := map[string][]string{}
	raw, err := os.ReadFile(CachePath())
	if err == nil {
		_ = json.Unmarshal(raw, &m)
	}
	return m
}

func saveCache(m map[string][]string) {
	_ = os.MkdirAll(Dir, 0o755)
	raw, err := json.MarshalIndent(m, "", "  ")
	if err == nil {
		_ = os.WriteFile(CachePath(), raw, 0o644)
	}
}
