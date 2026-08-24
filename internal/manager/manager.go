package manager

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"net"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/groundcat/wireguard-outbound-manager/internal/tunnel"
)

const (
	RunDir      = "/run/wireguard-outbound-manager"
	iface       = "wgom0"
	table       = "51888"
	tunnelMark  = "0x6d100000"
	inboundMark = "0x6d000000/0xff000000"
)

type Settings struct {
	ConfigDir string
	Interval  time.Duration
	Failures  int
	ProbeIP   string
	DryRun    bool
}

func DefaultSettings() Settings {
	return Settings{ConfigDir: "/etc/wireguard-outbound-manager/tunnels", Interval: 30 * time.Second, Failures: 3, ProbeIP: "1.1.1.1"}
}

type Status struct {
	State      string    `json:"state"`
	Active     string    `json:"active,omitempty"`
	Endpoint   string    `json:"endpoint,omitempty"`
	DirectIP   string    `json:"direct_ip,omitempty"`
	OutboundIP string    `json:"outbound_ip,omitempty"`
	LatencyMS  int64     `json:"latency_ms"`
	Failures   int       `json:"consecutive_failures"`
	Updated    time.Time `json:"updated"`
}
type Manager struct {
	cfg        Settings
	log        *log.Logger
	x          runner
	active     tunnel.Config
	status     Status
	oldSrcMark string
	directIP   string
}

func New(c Settings, l *log.Logger) *Manager {
	return &Manager{cfg: c, log: l, x: runner{c.DryRun, l}}
}

func (m *Manager) Run(ctx context.Context) error {
	r := Preflight(m.cfg.ConfigDir)
	if !r.Safe && !m.cfg.DryRun {
		return fmt.Errorf("preflight failed; run `wgom preflight` for details")
	}
	if err := os.MkdirAll(RunDir, 0700); err != nil {
		return err
	}
	defer m.cleanup(context.Background())
	m.oldSrcMark, _ = m.x.output(ctx, "sysctl", "-n", "net.ipv4.conf.all.src_valid_mark")
	_ = m.x.run(ctx, "sysctl", "-q", "-w", "net.ipv4.conf.all.src_valid_mark=1")
	configs, err := tunnel.LoadDir(m.cfg.ConfigDir)
	if err != nil {
		return err
	}
	configs = m.resolveConfigs(ctx, configs)
	m.directIP, err = m.traceIP(ctx, "")
	if err != nil {
		m.log.Printf("WARN could not establish direct-IP baseline error=%q", err)
	}
	if err = m.selectBest(ctx, configs, nil); err != nil {
		m.log.Printf("WARN no tunnel available; using direct internet and waiting error=%q", err)
		m.deactivate(ctx)
	}
	t := time.NewTicker(m.cfg.Interval)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-t.C:
			if m.active.Path == "" {
				configs, _ = tunnel.LoadDir(m.cfg.ConfigDir)
				configs = m.resolveConfigs(ctx, configs)
				if err := m.selectBest(ctx, configs, nil); err != nil {
					m.log.Printf("INFO still waiting for a healthy tunnel")
				}
				continue
			}
			_ = m.ensureFirewall(ctx)
			lat, err := m.probe(ctx, iface)
			if err == nil {
				m.status.Failures = 0
				m.status.LatencyMS = lat.Milliseconds()
				m.writeStatus()
				continue
			}
			m.status.Failures++
			m.writeStatus()
			m.log.Printf("WARN health check failed count=%d error=%q", m.status.Failures, err)
			if m.status.Failures >= m.cfg.Failures {
				failed := m.active.Path
				if err := m.selectBest(ctx, configs, map[string]bool{failed: true}); err != nil {
					m.log.Printf("WARN all fallbacks exhausted; disabling tunnel and restoring direct internet error=%q", err)
					m.deactivate(ctx)
				}
			}
		}
	}
}

func (m *Manager) resolveConfigs(ctx context.Context, cs []tunnel.Config) []tunnel.Config {
	for i := range cs {
		host, port, err := net.SplitHostPort(cs[i].Endpoint)
		if err != nil {
			m.log.Printf("WARN invalid endpoint tunnel=%q error=%q", cs[i].Name, err)
			continue
		}
		ips, err := net.DefaultResolver.LookupIP(ctx, "ip", host)
		if err != nil || len(ips) == 0 {
			m.log.Printf("WARN endpoint resolution failed tunnel=%q error=%q", cs[i].Name, err)
			continue
		}
		chosen := ips[0]
		for _, ip := range ips {
			if ip.To4() != nil {
				chosen = ip
				break
			}
		}
		cs[i].SetResolvedEndpoint(net.JoinHostPort(chosen.String(), port))
	}
	return cs
}

type scored struct {
	c tunnel.Config
	d time.Duration
}

func (m *Manager) selectBest(ctx context.Context, cs []tunnel.Config, skip map[string]bool) error {
	var ok []scored
	for i, c := range cs {
		if skip[c.Path] {
			continue
		}
		d, e := m.testCandidate(ctx, c, i)
		if e != nil {
			m.log.Printf("WARN candidate unavailable tunnel=%q error=%q", c.Name, e)
			continue
		}
		ok = append(ok, scored{c, d})
	}
	if len(ok) == 0 {
		return fmt.Errorf("no healthy tunnel found")
	}
	sort.Slice(ok, func(i, j int) bool { return ok[i].d < ok[j].d })
	var last error
	for _, candidate := range ok {
		if err := m.activate(ctx, candidate.c); err != nil {
			last = err
			m.log.Printf("WARN candidate activation failed tunnel=%q error=%q", candidate.c.Name, err)
			continue
		}
		outIP, err := m.traceIP(ctx, iface)
		if err != nil || (m.directIP != "" && outIP == m.directIP) {
			if err == nil {
				err = fmt.Errorf("Cloudflare Trace still reports direct IP %s", outIP)
			}
			last = err
			m.deactivate(ctx)
			continue
		}
		m.active = candidate.c
		m.status = Status{State: "connected", Active: candidate.c.Name, Endpoint: candidate.c.Endpoint, DirectIP: m.directIP, OutboundIP: outIP, LatencyMS: candidate.d.Milliseconds(), Updated: time.Now().UTC()}
		m.writeStatus()
		m.log.Printf("INFO tunnel active tunnel=%q latency=%s outbound_ip=%s", m.active.Name, candidate.d, outIP)
		return nil
	}
	return fmt.Errorf("no candidate changed outbound IP: %w", last)
}
func (m *Manager) testCandidate(ctx context.Context, c tunnel.Config, n int) (time.Duration, error) {
	name := "wgomt" + strconv.Itoa(n)
	probeTable := strconv.Itoa(51900 + n)
	probePriority := strconv.Itoa(19000 + n)
	_ = m.x.run(ctx, "ip", "link", "del", name)
	_ = m.x.run(ctx, "ip", "-4", "rule", "del", "priority", probePriority, "oif", name, "table", probeTable)
	if err := m.configure(ctx, c, name, tunnelMark); err != nil {
		return 0, err
	}
	defer m.x.run(context.Background(), "ip", "link", "del", name)
	if err := m.x.run(ctx, "ip", "-4", "route", "replace", "table", probeTable, "default", "dev", name); err != nil {
		return 0, err
	}
	if err := m.x.run(ctx, "ip", "-4", "rule", "add", "priority", probePriority, "oif", name, "table", probeTable); err != nil {
		return 0, err
	}
	defer m.x.run(context.Background(), "ip", "-4", "rule", "del", "priority", probePriority, "oif", name, "table", probeTable)
	defer m.x.run(context.Background(), "ip", "-4", "route", "flush", "table", probeTable)
	return m.probe(ctx, name)
}

func (m *Manager) traceIP(ctx context.Context, device string) (string, error) {
	args := []string{"--silent", "--show-error", "--fail", "--max-time", "8", "-4"}
	if device != "" {
		args = append(args, "--interface", device)
	}
	args = append(args, "https://www.cloudflare.com/cdn-cgi/trace")
	out, err := m.x.output(ctx, "curl", args...)
	if err != nil {
		return "", err
	}
	for _, line := range strings.Split(out, "\n") {
		if strings.HasPrefix(line, "ip=") {
			ip := strings.TrimSpace(strings.TrimPrefix(line, "ip="))
			if ip != "" {
				return ip, nil
			}
		}
	}
	return "", fmt.Errorf("Cloudflare Trace response has no IP")
}
func (m *Manager) configure(ctx context.Context, c tunnel.Config, name, mark string) error {
	p := filepath.Join(RunDir, name+".conf")
	if err := os.WriteFile(p, []byte(c.WGConfig), 0600); err != nil {
		return err
	}
	defer os.Remove(p)
	if err := m.x.run(ctx, "ip", "link", "add", "dev", name, "type", "wireguard"); err != nil {
		return err
	}
	rollback := true
	defer func() {
		if rollback {
			_ = m.x.run(context.Background(), "ip", "link", "del", name)
		}
	}()
	if err := m.x.run(ctx, "wg", "setconf", name, p); err != nil {
		return err
	}
	if err := m.x.run(ctx, "wg", "set", name, "fwmark", mark); err != nil {
		return err
	}
	for _, a := range c.Addresses {
		fam := "-4"
		if a.Addr().Is6() {
			fam = "-6"
		}
		if err := m.x.run(ctx, "ip", fam, "address", "add", a.String(), "dev", name); err != nil {
			return err
		}
	}
	if err := m.x.run(ctx, "ip", "link", "set", "mtu", strconv.Itoa(c.MTU), "up", "dev", name); err != nil {
		return err
	}
	rollback = false
	return nil
}
func (m *Manager) probe(ctx context.Context, name string) (time.Duration, error) {
	start := time.Now()
	err := m.x.run(ctx, "ping", "-n", "-I", name, "-c", "1", "-W", "5", m.cfg.ProbeIP)
	return time.Since(start), err
}
func (m *Manager) activate(ctx context.Context, c tunnel.Config) error {
	_ = m.removePolicy(ctx)
	_ = m.x.run(ctx, "ip", "link", "del", iface)
	if err := m.configure(ctx, c, iface, tunnelMark); err != nil {
		return err
	}
	// Install reply-path marking before outbound policy to protect existing sessions.
	if err := m.ensureFirewall(ctx); err != nil {
		return err
	}
	for _, fam := range []string{"-4", "-6"} {
		if err := m.x.run(ctx, "ip", fam, "route", "replace", "table", table, "default", "dev", iface); err != nil {
			if fam == "-6" {
				continue
			}
			return err
		}
		_ = m.x.run(ctx, "ip", fam, "rule", "add", "priority", "5100", "fwmark", inboundMark, "table", "main")
		_ = m.x.run(ctx, "ip", fam, "rule", "add", "priority", "10000", "not", "fwmark", tunnelMark, "table", table)
		_ = m.x.run(ctx, "ip", fam, "rule", "add", "priority", "10010", "table", "main", "suppress_prefixlength", "0")
	}
	return nil
}
func (m *Manager) ensureFirewall(ctx context.Context) error {
	// Connection marking only; no filtering. The service is deliberately fail-open.
	for _, ipt := range []string{"iptables", "ip6tables"} {
		if err := m.ensureFirewallFamily(ctx, ipt); err != nil {
			return err
		}
	}
	return nil
}
func (m *Manager) ensureFirewallFamily(ctx context.Context, ipt string) error {
	for _, spec := range [][]string{{"-t", "mangle", "-N", "WGOM_INBOUND"}} {
		if !m.x.ok(ctx, ipt, append([]string{"-t", spec[1], "-S", spec[3]}, spec[4:]...)...) {
			_ = m.x.run(ctx, ipt, spec...)
		}
	}
	if !m.x.ok(ctx, ipt, "-t", "mangle", "-C", "PREROUTING", "-j", "WGOM_INBOUND") {
		if err := m.x.run(ctx, ipt, "-t", "mangle", "-I", "PREROUTING", "1", "-j", "WGOM_INBOUND"); err != nil {
			return err
		}
	}
	if err := m.x.run(ctx, ipt, "-t", "mangle", "-F", "WGOM_INBOUND"); err != nil {
		return err
	}
	for _, a := range [][]string{{"-i", iface, "-j", "RETURN"}, {"-i", "lo", "-j", "RETURN"}, {"-m", "conntrack", "--ctdir", "ORIGINAL", "-j", "CONNMARK", "--set-xmark", inboundMark}} {
		args := append([]string{"-t", "mangle", "-A", "WGOM_INBOUND"}, a...)
		if err := m.x.run(ctx, ipt, args...); err != nil {
			return err
		}
	}
	restore := []string{"-m", "connmark", "--mark", inboundMark, "-j", "CONNMARK", "--restore-mark", "--nfmask", "0xff000000", "--ctmask", "0xff000000"}
	check := append([]string{"-t", "mangle", "-C", "OUTPUT"}, restore...)
	if !m.x.ok(ctx, ipt, check...) {
		args := append([]string{"-t", "mangle", "-I", "OUTPUT", "1"}, restore...)
		if err := m.x.run(ctx, ipt, args...); err != nil {
			return err
		}
	}
	return nil
}
func (m *Manager) removePolicy(ctx context.Context) error {
	for _, fam := range []string{"-4", "-6"} {
		_ = m.x.run(ctx, "ip", fam, "rule", "del", "priority", "5100", "fwmark", inboundMark, "table", "main")
		_ = m.x.run(ctx, "ip", fam, "rule", "del", "priority", "10000", "not", "fwmark", tunnelMark, "table", table)
		_ = m.x.run(ctx, "ip", fam, "rule", "del", "priority", "10010", "table", "main", "suppress_prefixlength", "0")
		_ = m.x.run(ctx, "ip", fam, "route", "flush", "table", table)
	}
	return nil
}
func (m *Manager) cleanup(ctx context.Context) {
	_ = m.removePolicy(ctx)
	for _, ipt := range []string{"iptables", "ip6tables"} {
		for _, x := range [][]string{{"-t", "mangle", "-D", "OUTPUT", "-m", "connmark", "--mark", inboundMark, "-j", "CONNMARK", "--restore-mark", "--nfmask", "0xff000000", "--ctmask", "0xff000000"}, {"-t", "mangle", "-D", "PREROUTING", "-j", "WGOM_INBOUND"}, {"-t", "mangle", "-F", "WGOM_INBOUND"}, {"-t", "mangle", "-X", "WGOM_INBOUND"}} {
			_ = m.x.run(ctx, ipt, x...)
		}
	}
	_ = m.x.run(ctx, "ip", "link", "del", iface)
	if strings.TrimSpace(m.oldSrcMark) != "" {
		_ = m.x.run(ctx, "sysctl", "-q", "-w", "net.ipv4.conf.all.src_valid_mark="+strings.TrimSpace(m.oldSrcMark))
	}
	_ = os.Remove(filepath.Join(RunDir, "status.json"))
}
func (m *Manager) deactivate(ctx context.Context) {
	_ = m.removePolicy(ctx)
	_ = m.x.run(ctx, "ip", "link", "del", iface)
	for _, ipt := range []string{"iptables", "ip6tables"} {
		for _, x := range [][]string{{"-t", "mangle", "-D", "OUTPUT", "-m", "connmark", "--mark", inboundMark, "-j", "CONNMARK", "--restore-mark", "--nfmask", "0xff000000", "--ctmask", "0xff000000"}, {"-t", "mangle", "-D", "PREROUTING", "-j", "WGOM_INBOUND"}, {"-t", "mangle", "-F", "WGOM_INBOUND"}, {"-t", "mangle", "-X", "WGOM_INBOUND"}} {
			_ = m.x.run(ctx, ipt, x...)
		}
	}
	m.active = tunnel.Config{}
	m.status = Status{State: "waiting", DirectIP: m.directIP, OutboundIP: m.directIP}
	m.writeStatus()
}
func (m *Manager) writeStatus() {
	m.status.Updated = time.Now().UTC()
	b, _ := json.MarshalIndent(m.status, "", "  ")
	_ = os.WriteFile(filepath.Join(RunDir, "status.json"), append(b, '\n'), 0644)
}
