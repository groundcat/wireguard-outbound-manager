package manager

import (
	"fmt"
	"github.com/groundcat/wireguard-outbound-manager/internal/tunnel"
	"os"
	"os/exec"
	"runtime"
	"strings"
)

type Check struct {
	Name   string `json:"name"`
	OK     bool   `json:"ok"`
	Detail string `json:"detail"`
}
type Report struct {
	Safe   bool    `json:"safe"`
	Checks []Check `json:"checks"`
}

func Preflight(dir string) Report {
	r := Report{Safe: true}
	add := func(n string, ok bool, d string) {
		r.Checks = append(r.Checks, Check{n, ok, d})
		if !ok {
			r.Safe = false
		}
	}
	add("operating_system", runtime.GOOS == "linux", runtime.GOOS)
	add("root", os.Geteuid() == 0, fmt.Sprintf("uid=%d", os.Geteuid()))
	for _, x := range []string{"ip", "wg", "iptables", "ip6tables", "ping", "curl"} {
		_, e := exec.LookPath(x)
		add("command_"+x, e == nil, fmt.Sprint(e))
	}
	cs, e := tunnel.LoadDir(dir)
	add("tunnel_configs", e == nil, func() string {
		if e != nil {
			return e.Error()
		}
		return fmt.Sprintf("%d valid configuration(s)", len(cs))
	}())
	if e == nil {
		for _, c := range cs {
			st, se := os.Stat(c.Path)
			ok := se == nil && st.Mode().Perm()&0077 == 0
			add("permissions_"+c.Name, ok, func() string {
				if se != nil {
					return se.Error()
				}
				return st.Mode().Perm().String()
			}())
		}
	}
	b, _ := os.ReadFile("/etc/os-release")
	supported := strings.Contains(string(b), "ID=debian") || strings.Contains(string(b), "ID=ubuntu")
	add("distribution", supported, "Debian or Ubuntu required")
	return r
}
