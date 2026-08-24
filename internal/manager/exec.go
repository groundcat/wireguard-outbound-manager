package manager

import (
	"context"
	"fmt"
	"log"
	"os/exec"
	"strings"
)

type runner struct {
	dry bool
	log *log.Logger
}

func (r runner) run(ctx context.Context, name string, args ...string) error {
	r.log.Printf("DEBUG command program=%s args=%q", name, args)
	if r.dry {
		return nil
	}
	c := exec.CommandContext(ctx, name, args...)
	out, err := c.CombinedOutput()
	if err != nil {
		return fmt.Errorf("%s %s: %w: %s", name, strings.Join(args, " "), err, strings.TrimSpace(string(out)))
	}
	return nil
}
func (r runner) output(ctx context.Context, name string, args ...string) (string, error) {
	if r.dry {
		return "", nil
	}
	c := exec.CommandContext(ctx, name, args...)
	b, e := c.CombinedOutput()
	if e != nil {
		return "", fmt.Errorf("%s: %w: %s", name, e, b)
	}
	return strings.TrimSpace(string(b)), nil
}
func (r runner) ok(ctx context.Context, name string, args ...string) bool {
	if r.dry {
		return true
	}
	return exec.CommandContext(ctx, name, args...).Run() == nil
}
