//go:build windows

package killswitch

import (
	"github.com/tailscale/wf"
	"golang.org/x/sys/windows"
)

// Static, project-unique GUIDs. These never change: they are how we find
// and remove our own objects after a crash, reinstall or panic-disable.
// (Generated once; do not regenerate.)
var (
	providerID = wf.ProviderID(windows.GUID{
		Data1: 0x7a3c9e11, Data2: 0x54d2, Data3: 0x4b8f,
		Data4: [8]byte{0x9a, 0x1e, 0x33, 0x71, 0xc4, 0x0d, 0xbe, 0xef},
	})
	sublayerID = wf.SublayerID(windows.GUID{
		Data1: 0x7a3c9e12, Data2: 0x54d2, Data3: 0x4b8f,
		Data4: [8]byte{0x9a, 0x1e, 0x33, 0x71, 0xc4, 0x0d, 0xbe, 0xef},
	})
)

// newRuleID generates a random GUID for a rule. Rules are always located
// via their Provider field, so random IDs are fine.
func newRuleID() wf.RuleID {
	g, err := windows.GenerateGUID()
	if err != nil {
		// Practically unreachable; a zero GUID would be rejected by WFP,
		// which is the safe failure mode.
		return wf.RuleID{}
	}
	return wf.RuleID(g)
}
