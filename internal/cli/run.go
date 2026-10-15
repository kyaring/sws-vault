package cli

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"strings"
	"time"
)

func Run(args []string) error {
	c, args, e := LoadConfig(args)
	if e != nil {
		return e
	}
	var binds []string
	idx := 0
	for idx < len(args) {
		switch args[idx] {
		case "--env":
			if idx+1 >= len(args) {
				return errors.New("--env requires NAME=vault:ns/id")
			}
			binds = append(binds, args[idx+1])
			idx += 2
		case "--secret":
			if idx+1 >= len(args) {
				return errors.New("--secret requires vault:ns/id")
			}
			if !strings.HasPrefix(args[idx+1], "vault:") {
				return errors.New("--secret requires a vault reference")
			}
			binds = append(binds, "SWSV_SECRET="+args[idx+1])
			idx += 2
		default:
			goto optionsDone
		}
	}
optionsDone:
	if idx >= len(args) || args[idx] != "--" || idx+1 >= len(args) {
		return errors.New("usage: run [--env-file FILE] [--env NAME=vault:ns/id] [--secret vault:ns/id] -- command args")
	}
	cmdArgs := args[idx+1:]
	env := map[string]string{}
	for _, v := range os.Environ() {
		k, val, ok := strings.Cut(v, "=")
		if ok {
			env[k] = val
		}
	}
	var values []string
	for _, b := range binds {
		k, ref, ok := strings.Cut(b, "=")
		if !ok || k == "" || strings.ContainsAny(k, " \t\r\n=") {
			return errors.New("invalid --env binding")
		}
		if !strings.HasPrefix(ref, "vault:") {
			return errors.New("environment values must use vault references")
		}
		value, e := c.Resolve(ref)
		if e != nil {
			for i := range values {
				values[i] = ""
			}
			return e
		}
		env[k] = value
		values = append(values, value)
	}
	defer func() {
		for i := range values {
			values[i] = ""
		}
	}()
	ctx, cancel := context.WithTimeout(context.Background(), 24*time.Hour)
	defer cancel()
	cmd := exec.CommandContext(ctx, cmdArgs[0], cmdArgs[1:]...)
	for k, v := range env {
		cmd.Env = append(cmd.Env, k+"="+v)
	}
	out := NewRedactor(os.Stdout, values)
	er := NewRedactor(os.Stderr, values)
	cmd.Stdout = out
	cmd.Stderr = er
	err := cmd.Run()
	_ = out.Flush()
	_ = er.Flush()
	if err != nil {
		var ee *exec.ExitError
		if errors.As(err, &ee) {
			return ee
		}
		return fmt.Errorf("run command failed: %w", err)
	}
	return nil
}
