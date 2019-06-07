// package exec implements a Runner using os/exec

package exec

import (
	"context"
	"fmt"
	"io"
	"os"
	"os/exec"
	"strings"
	"sync"
	"time"
)

//go:generate gobin -m -run github.com/maxbrunsfeld/counterfeiter/v6 -o ./fakes/replacer.go --fake-name Replacer . Replacer

// A Replacer replaces strings
type Replacer interface {
	Replace(string) (string, error)
}

// A Runner runs commands with `os/exec.Cmd`s
type Runner struct {
	args          []string
	in            io.Reader
	name          string
	originalEnv   []string
	out           io.Writer
	replacer      Replacer
	runningInputs commandInputs
	started       bool

	reqlock        sync.Mutex
	stopRequest    chan struct{}
	restartRequest chan struct{}
}

// NewRunner creates a new Runner
func NewRunner(
	in io.Reader,
	out io.Writer,
	env []string,
	replacer Replacer,
	name string,
	args ...string) *Runner {
	return &Runner{
		stopRequest:    make(chan struct{}, 100),
		restartRequest: make(chan struct{}, 100),
		in:             in,
		out:            out,
		originalEnv:    env,
		replacer:       replacer,
		name:           name,
		args:           args,
		reqlock:        sync.Mutex{},
	}
}

func (r *Runner) Run() error {
	runErrChan := make(chan error)
	for {
		// render inputs. Note: the inputs may be
		// dynamic, so this may change on each
		// iteration of the loop
		inputs, err := r.renderInputs()
		if err != nil {
			return fmt.Errorf("failed to render command inputs: %v", err)
		}
		r.runningInputs = inputs

		// Create a new command
		// Note: we create a context here so that
		// we can cancel the command if asked.
		ctx, cancel := context.WithCancel(context.Background())
		cmd := exec.CommandContext(ctx, inputs.name, inputs.args...)
		cmd.Env = inputs.env
		cmd.Stdin = r.in
		cmd.Stdout = r.out

		// Run the command
		r.started = true
		cancelled := false
		go func() {
			err := cmd.Run()

			// Ignore "signal: killed" errors, which will
			// fire when we cancel the command context.
			//TODO(donald): find a cleaner way to determine the error type
			if err != nil && !(cancelled && err.Error() == "signal: killed") {
				runErrChan <- fmt.Errorf("error running command: %v", err)
				return
			}
			runErrChan <- nil
		}()

		select {
		case err := <-runErrChan:
			// command finished on its own
			cancel()
			return err
		case <-r.stopRequest:
			cancelled = true
			cancel()
			// wait for the running command to exit
			timeout := time.After(5 * time.Second)
			select {
			case <-timeout:
				return fmt.Errorf("timed out waiting for command to cancel")
			case err := <-runErrChan:
				if err != nil {
					return fmt.Errorf("error from cancelled command: %v", err)
				}
			}

			// close and rebuild request channels
			r.reqlock.Lock()
			close(r.stopRequest)
			close(r.restartRequest)
			r.stopRequest = make(chan struct{}, 100)
			r.restartRequest = make(chan struct{}, 100)
			r.reqlock.Unlock()

			return nil

		case <-r.restartRequest:
			cancelled = true
			cancel()
			// wait for the running command to exit
			timeout := time.After(5 * time.Second)
			select {
			case <-timeout:
				return fmt.Errorf("timed out waiting for command to cancel")
			case err := <-runErrChan:
				if err != nil {
					return fmt.Errorf("error from cancelled command: %v", err)
				}
			}

			// close and rebuild request channels
			r.reqlock.Lock()
			close(r.stopRequest)
			close(r.restartRequest)
			r.stopRequest = make(chan struct{}, 100)
			r.restartRequest = make(chan struct{}, 100)
			r.reqlock.Unlock()

			continue
		}
	}
}

// HasConfigurationChanged returns true if the
// configuration, evaluated now, is different
// from the configuration that was used to
// initially run the command.
//
// If the command is not running,
// HasConfigurationChanged returns false.
func (r *Runner) HasConfigurationChanged() (bool, error) {
	if !r.started {
		return false, nil
	}
	newInputs, err := r.renderInputs()
	if err != nil {
		return false, fmt.Errorf("failed to render command inputs: %v", err)
	}

	return r.runningInputs.differsFrom(newInputs), nil
}

type commandInputs struct {
	env  []string
	args []string
	name string
}

func (a commandInputs) differsFrom(b commandInputs) bool {
	if a.name != b.name {
		return true
	}
	if len(a.env) != len(b.env) {
		return true
	}
	for i, v := range a.env {
		if b.env[i] != v {
			return true
		}
	}
	if len(a.args) != len(b.args) {
		return true
	}
	for i, v := range a.args {
		if b.args[i] != v {
			return true
		}
	}
	return false
}

func (r *Runner) renderInputs() (commandInputs, error) {
	// replace all values in the environment
	env, err := replaceStrings(r.originalEnv, r.replacer)
	if err != nil {
		return commandInputs{}, fmt.Errorf("failed to replace values in the environment: %v", err)
	}

	// Many commands will include uninterpolated
	// variables, like `echo $FOO $BAR`.
	// We should re-interpolate those variables
	// with the newly-replaced environment
	args := make([]string, len(r.args))
	copy(args, r.args)
	m := envMap(env)
	for i, arg := range args {
		args[i] = os.Expand(arg, func(s string) string { return m[s] })
	}

	// TODO(donald): if the args contain a .redacted
	// filename, like `cat myconfig.yaml.redacted`,
	// we should attempt to create an in-memory file
	// with replaced contents, and change the
	// reference in the command to point to it

	return commandInputs{
		env:  env,
		args: args,
		name: r.name,
	}, nil
}

// Stop stops the running command
func (r *Runner) Stop() {
	r.stopRequest <- struct{}{}
}

// Restart restarts the running command
func (r *Runner) Restart() {
	r.restartRequest <- struct{}{}
}

// replaceStrings runs the Replacer
// on all strings in an array (map fn)
func replaceStrings(ss []string, r Replacer) ([]string, error) {
	replaced := make([]string, len(ss))
	for i, s := range ss {
		rs, err := r.Replace(s)
		if err != nil {
			return nil, fmt.Errorf(`failed to replace string %v ("%s"): %v`, i, s, err)
		}
		replaced[i] = rs
	}
	return replaced, nil
}

// envMap breaks an environment array, an array
// of strings like ["FOO=bar", "BAZ=bop"])
// into a map like {"FOO": "bar", "BAZ": "bop"}
func envMap(env []string) map[string]string {
	m := make(map[string]string)
	for _, s := range env {
		ss := strings.Split(s, "=")
		if len(ss) != 2 {
			continue
		}
		m[ss[0]] = ss[1]
	}
	return m
}
