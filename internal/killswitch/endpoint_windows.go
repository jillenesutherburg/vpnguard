//go:build windows

package killswitch

import (
	"fmt"
	"net/netip"

	"github.com/tailscale/wf"
)

// EndpointFrom builds an Endpoint from string config values.
func EndpointFrom(ip string, port uint16, proto string) (Endpoint, error) {
	addr, err := netip.ParseAddr(ip)
	if err != nil {
		return Endpoint{}, fmt.Errorf("bad endpoint IP %q: %w", ip, err)
	}
	p := wf.IPProtoUDP
	if proto == "tcp" {
		p = wf.IPProtoTCP
	}
	return Endpoint{Addr: addr, Port: port, Proto: p}, nil
}
