package manager

import "testing"

func TestDefaults(t *testing.T) {
	c := DefaultSettings()
	if c.Interval.String() != "30s" || c.Failures != 3 {
		t.Fatalf("unexpected defaults: %#v", c)
	}
}
