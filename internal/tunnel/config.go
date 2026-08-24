package tunnel

import (
	"bufio"
	"fmt"
	"net/netip"
	"os"
	"path/filepath"
	"strconv"
	"strings"
)

type Config struct {
	Path, Name, Endpoint   string
	Addresses              []netip.Prefix
	MTU                    int
	WGConfig               string
	CoversIPv4, CoversIPv6 bool
}

var quickOnly = map[string]bool{"address": true, "dns": true, "mtu": true, "table": true, "preup": true, "postup": true, "predown": true, "postdown": true, "saveconfig": true}

func LoadDir(dir string) ([]Config, error) {
	files, err := filepath.Glob(filepath.Join(dir, "*.conf"))
	if err != nil {
		return nil, err
	}
	if len(files) == 0 {
		return nil, fmt.Errorf("no .conf files in %s", dir)
	}
	out := make([]Config, 0, len(files))
	for _, f := range files {
		c, err := Parse(f)
		if err != nil {
			return nil, err
		}
		out = append(out, c)
	}
	return out, nil
}

func Parse(path string) (Config, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return Config{}, err
	}
	c := Config{Path: path, Name: strings.TrimSuffix(filepath.Base(path), filepath.Ext(path)), MTU: 1420}
	s := bufio.NewScanner(strings.NewReader(string(b)))
	section := ""
	var wg []string
	for s.Scan() {
		line := strings.TrimSpace(s.Text())
		if strings.HasPrefix(line, "[") {
			section = strings.ToLower(line)
			wg = append(wg, line)
			continue
		}
		if line == "" || strings.HasPrefix(line, "#") {
			wg = append(wg, s.Text())
			continue
		}
		parts := strings.SplitN(line, "=", 2)
		if len(parts) != 2 {
			return c, fmt.Errorf("%s: invalid line", path)
		}
		key, val := strings.ToLower(strings.TrimSpace(parts[0])), strings.TrimSpace(parts[1])
		if section == "[interface]" {
			switch key {
			case "address":
				for _, a := range strings.Split(val, ",") {
					p, e := netip.ParsePrefix(strings.TrimSpace(a))
					if e != nil {
						return c, fmt.Errorf("%s: address: %w", path, e)
					}
					c.Addresses = append(c.Addresses, p)
				}
			case "mtu":
				c.MTU, _ = strconv.Atoi(val)
			}
		}
		if section == "[peer]" && key == "allowedips" {
			for _, raw := range strings.Split(val, ",") {
				p, e := netip.ParsePrefix(strings.TrimSpace(raw))
				if e != nil {
					return c, fmt.Errorf("%s: AllowedIPs: %w", path, e)
				}
				if p.Bits() == 0 {
					if p.Addr().Is4() {
						c.CoversIPv4 = true
					} else {
						c.CoversIPv6 = true
					}
				}
			}
		}
		if section == "[peer]" && key == "endpoint" {
			c.Endpoint = val
		}
		if !quickOnly[key] {
			wg = append(wg, s.Text())
		}
	}
	if err := s.Err(); err != nil {
		return c, err
	}
	if c.Endpoint == "" || len(c.Addresses) == 0 {
		return c, fmt.Errorf("%s: requires Address and Endpoint", path)
	}
	if !c.CoversIPv4 || !c.CoversIPv6 {
		return c, fmt.Errorf("%s: AllowedIPs must cover both 0.0.0.0/0 and ::/0", path)
	}
	c.WGConfig = strings.Join(wg, "\n") + "\n"
	return c, nil
}

// SetResolvedEndpoint replaces only the wg Endpoint directive while retaining
// the original hostname in Config.Endpoint for status and future re-resolution.
func (c *Config) SetResolvedEndpoint(endpoint string) {
	lines := strings.Split(c.WGConfig, "\n")
	for i, line := range lines {
		p := strings.SplitN(strings.TrimSpace(line), "=", 2)
		if len(p) == 2 && strings.EqualFold(strings.TrimSpace(p[0]), "Endpoint") {
			lines[i] = "Endpoint = " + endpoint
		}
	}
	c.WGConfig = strings.Join(lines, "\n")
}
