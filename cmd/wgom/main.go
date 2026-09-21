package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"log"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"

	"github.com/groundcat/wireguard-outbound-manager/internal/manager"
)

var version = "dev"

func main() {
	logger := log.New(os.Stdout, "wgom: ", log.LstdFlags|log.LUTC)
	if len(os.Args) < 2 {
		usage()
		os.Exit(2)
	}
	switch os.Args[1] {
	case "version":
		fmt.Println(version)
	case "preflight":
		fs := flag.NewFlagSet("preflight", flag.ExitOnError)
		dir := fs.String("config-dir", "/etc/wireguard-outbound-manager/tunnels", "tunnel configuration directory")
		_ = fs.Parse(os.Args[2:])
		r := manager.Preflight(*dir)
		b, _ := json.MarshalIndent(r, "", "  ")
		fmt.Println(string(b))
		if !r.Safe {
			os.Exit(1)
		}
	case "run":
		fs := flag.NewFlagSet("run", flag.ExitOnError)
		cfg := manager.DefaultSettings()
		fs.StringVar(&cfg.ConfigDir, "config-dir", cfg.ConfigDir, "tunnel configuration directory")
		fs.DurationVar(&cfg.Interval, "interval", cfg.Interval, "health check interval")
		fs.IntVar(&cfg.Failures, "failures", cfg.Failures, "consecutive failures before failover")
		fs.StringVar(&cfg.ProbeIP, "probe-ip", cfg.ProbeIP, "IPv4 connectivity probe")
		fs.BoolVar(&cfg.DryRun, "dry-run", false, "log changes without applying them")
		fs.BoolVar(&cfg.MailBypass, "mail-bypass", cfg.MailBypass, "route outbound IMAP/POP3/SMTP ports around the tunnel")
		_ = fs.Parse(os.Args[2:])
		ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
		defer cancel()
		m := manager.New(cfg, logger)
		if err := m.Run(ctx); err != nil && !errors.Is(err, context.Canceled) {
			logger.Printf("ERROR manager stopped error=%q", err)
			os.Exit(1)
		}
	case "status":
		data, err := os.ReadFile(filepath.Join(manager.RunDir, "status.json"))
		if err != nil {
			fmt.Fprintln(os.Stderr, "not running:", err)
			os.Exit(1)
		}
		fmt.Print(string(data))
	default:
		usage()
		os.Exit(2)
	}
}

func usage() { fmt.Fprintln(os.Stderr, "usage: wgom <preflight|run|status|version> [options]") }
