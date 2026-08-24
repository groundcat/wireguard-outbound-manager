package tunnel

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestParseStripsWGQuickFields(t *testing.T) {
	d := t.TempDir()
	p := filepath.Join(d, "one.conf")
	s := "[Interface]\nAddress = 10.0.0.2/32, fd00::2/128\nPrivate" + "Key = test-only\nDNS = 1.1.1.1\nMTU = 1300\nPostUp = bad\n[Peer]\nPublicKey = test-only\nEndpoint = vpn.example:51820\nAllowedIPs = 0.0.0.0/0, ::/0\n"
	if err := os.WriteFile(p, []byte(s), 0600); err != nil {
		t.Fatal(err)
	}
	c, err := Parse(p)
	if err != nil {
		t.Fatal(err)
	}
	if c.Endpoint != "vpn.example:51820" || c.MTU != 1300 || len(c.Addresses) != 2 {
		t.Fatalf("bad parse: %#v", c)
	}
	if !c.CoversIPv4 || !c.CoversIPv6 {
		t.Fatal("default routes not detected")
	}
	c.SetResolvedEndpoint("192.0.2.10:51820")
	if !strings.Contains(c.WGConfig, "Endpoint = 192.0.2.10:51820") || strings.Contains(c.WGConfig, "vpn.example") {
		t.Fatal("endpoint was not replaced")
	}
	if strings.Contains(c.WGConfig, "Address") || strings.Contains(c.WGConfig, "DNS") || strings.Contains(c.WGConfig, "PostUp") {
		t.Fatal("wg-quick directive leaked")
	}
}
