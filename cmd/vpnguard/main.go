//go:build windows

// vpnguard — fail-closed VPN kill switch for Windows.
//
// Usage:
//
//	vpnguard init                      write example config to ProgramData
//	vpnguard service install           install + start the Windows service
//	vpnguard service uninstall         stop + remove the service
//	vpnguard service run               run the service loop in foreground
//	vpnguard status                    show kill switch state
//	vpnguard enable                    apply kill switch once (manual mode)
//	vpnguard disable                   remove all VPNGuard firewall rules
//	vpnguard panic                     emergency: same as disable, minimal deps
//	vpnguard interfaces                list adapters with LUIDs
package main

import (
	"fmt"
	"os"

	"github.com/YOURNAME/vpnguard/internal/config"
	"github.com/YOURNAME/vpnguard/internal/killswitch"
	"github.com/YOURNAME/vpnguard/internal/wsvc"
	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/svc"
)

var version = "dev" // injected via -ldflags at build time

func main() {
	if err := run(); err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		os.Exit(1)
	}
}

func run() error {
	// When started by the Service Control Manager, argv is
	// ["vpnguard.exe", "service", "run"]; handle it before anything else.
	if isSvc, _ := svc.IsWindowsService(); isSvc {
		return wsvc.Run(false)
	}

	if len(os.Args) < 2 {
		usage()
		return nil
	}
	switch os.Args[1] {

	case "version":
		fmt.Println("vpnguard", version)
		return nil

	case "init":
		if err := config.WriteExample(); err != nil {
			return err
		}
		fmt.Println("wrote", config.Path(), "- edit it, then run: vpnguard service install")
		return nil

	case "interfaces":
		out, err := killswitch.ListInterfaces()
		if err != nil {
			return err
		}
		fmt.Print(out)
		return nil

	case "diag":
		return wsvc.Diagnose(os.Stdout)

	case "service":
		if len(os.Args) < 3 {
			usage()
			return nil
		}
		switch os.Args[2] {
		case "install":
			requireAdmin()
			if err := wsvc.Install(); err != nil {
				return err
			}
			fmt.Println("service installed and started")
			return nil
		case "uninstall":
			requireAdmin()
			if err := wsvc.Uninstall(); err != nil {
				return err
			}
			fmt.Println("service removed (firewall rules are kept; run `vpnguard disable` to lift the kill switch)")
			return nil
		case "run":
			requireAdmin()
			return wsvc.Run(true)
		}
		usage()
		return nil

	case "status":
		m, err := killswitch.New(true) // статическая сессия: только читаем
		if err != nil {
			return err
		}
		defer m.Close()
		n, err := m.ActiveRuleCount()
		if err != nil {
			return err
		}
		if n == 0 {
			fmt.Println("kill switch: DISABLED (no VPNGuard rules installed)")
		} else {
			fmt.Printf("kill switch: ACTIVE (%d rules installed)\n", n)
		}
		return nil

	case "enable":
		requireAdmin()
		cfg, err := config.Load()
		if err != nil {
			return err
		}
		ksCfg, err := wsvc.BuildKillswitchConfig(cfg, nil)
		if err != nil {
			return err
		}
		luids, err := killswitch.FindTunnelLUIDs(cfg.Killswitch.TunnelInterfaces)
		if err != nil {
			return err
		}
		ksCfg.TunnelLUIDs = luids
		if !cfg.Killswitch.Persistent {
			fmt.Println("ВНИМАНИЕ: persistent=false — фильтры мягкого режима живут, пока жив процесс;")
			fmt.Println("для ручного enable из CLI это значит «до закрытия сессии». Мягкий режим имеет смысл только в службе.")
		}
		m, err := killswitch.New(cfg.Killswitch.Persistent)
		if err != nil {
			return err
		}
		defer m.Close()
		if err := m.Apply(ksCfg); err != nil {
			return err
		}
		fmt.Printf("kill switch enabled (tunnel adapters up: %d)\n", len(luids))
		return nil

	case "disable", "panic":
		requireAdmin()
		m, err := killswitch.New(true) // статическая сессия: снимаем в т.ч. persistent-объекты
		if err != nil {
			return err
		}
		defer m.Close()
		if err := m.Disable(); err != nil {
			return err
		}
		fmt.Println("all VPNGuard firewall rules removed; network unrestricted")
		return nil
	}

	usage()
	return nil
}

func requireAdmin() {
	if !windows.GetCurrentProcessToken().IsElevated() {
		fmt.Fprintln(os.Stderr, "error: this command requires administrator rights")
		os.Exit(1)
	}
}

func usage() {
	fmt.Println(`vpnguard - fail-closed VPN kill switch

  vpnguard init                 write example config
  vpnguard service install      install + start Windows service
  vpnguard service uninstall    remove service (rules stay!)
  vpnguard service run          run in foreground (debug)
  vpnguard status               kill switch state
  vpnguard enable               apply once, manually
  vpnguard disable | panic      remove ALL VPNGuard rules
  vpnguard interfaces           list network adapters with LUIDs
  vpnguard diag                 print paths, service state, config presence, log tail
  vpnguard version`)
}
