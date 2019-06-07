package redactr

import (
	"fmt"
	"time"
)

//go:generate gobin -m -run github.com/maxbrunsfeld/counterfeiter/v6 -o ./fakes/runner.go --fake-name Runner . Runner

// A Runner runs.
type Runner interface {
	// Run runs the command. The runner should replace
	// relevant values with the Replacer. For example,
	// a command-line runner may replace values in
	// the environment.
	Run() error

	// HasConfigurationChanged should re-evaluate any
	// dynamic configuration, and return true if that
	// configuration differs from the configuration
	// that was used to Run().
	//
	// If the Runner is not running, it should
	// return false.
	HasConfigurationChanged() (bool, error)

	// Restart should restart the running runner.
	Restart()

	// Stop should stop the running Runner
	//
	Stop()
}

// ExecConfig is used to configure a call
// to Exec()
type ExecConfig struct {
	onEnvChange      OnEnvChangeBehavior
	reevaluationFreq time.Duration
}

// An ExecOption changes the way that Exec behaves
type ExecOption func(*ExecConfig)

// RestartIfEnvChanges tells Exec to periodically
// re-check the configuration of the running command.
// If it changes, Exec will restart the command.
func RestartIfEnvChanges(d time.Duration) ExecOption {
	return func(c *ExecConfig) {
		c.onEnvChange = Restart
		c.reevaluationFreq = d
	}
}

// StopIfEnvChanges tells Exec to periodically
// re-check the configuration of the running command.
// If it changes, Exec will stop the command.
func StopIfEnvChanges(d time.Duration) ExecOption {
	return func(c *ExecConfig) {
		c.onEnvChange = Stop
		c.reevaluationFreq = d
	}
}

// OnEnvChangeBehavior determines the behavior of the
// Tool if it discovers that the environment has changed
type OnEnvChangeBehavior int8

// Available OnEnvChangeBehaviors
const (
	DoNothing = OnEnvChangeBehavior(iota) // default: do nothing
	Stop
	Restart
)

// Exec runs the Runner.
//
// When called with the RestartIfEnvChanges or
// StopIfEnvChanges option, Exec will periodically
// re-evaluate the environment. If the environment
// has changed, Exec will restart or stop the runner
// as requested.
func Exec(runner Runner, opts ...ExecOption) error {
	conf := &ExecConfig{}
	for _, o := range opts {
		o(conf)
	}

	// If the caller has requested that we periodically
	// recheck the environment, do so in a goroutine
	reevaluationErrChan := make(chan error)
	if conf.reevaluationFreq > 0 && conf.onEnvChange != DoNothing {
		go func() {
			for {
				<-time.After(conf.reevaluationFreq)
				hasChanged, err := runner.HasConfigurationChanged()
				if err != nil {
					reevaluationErrChan <- fmt.Errorf("failed to determine if configuration has changed: %v", err)
					return
				}
				if hasChanged {
					switch {
					case conf.onEnvChange == Stop:
						runner.Stop()
					case conf.onEnvChange == Restart:
						runner.Restart()
					}
				}
			}
		}()
	}

	runErrChan := make(chan error)
	go func() {
		err := runner.Run()
		if err != nil {
			runErrChan <- err
			return
		}
		runErrChan <- nil
	}()

	// wait for an error from one of the channels
	select {
	case err := <-runErrChan:
		return err
	case err := <-reevaluationErrChan:
		return err
	}
}
