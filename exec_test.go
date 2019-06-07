package redactr_test

import (
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/dhoelle/redactr"
	"github.com/dhoelle/redactr/fakes"
)

func Test_Exec(t *testing.T) {
	t.Run("it should run a runner, and exit when that command is finished", func(t *testing.T) {
		runner := &fakes.Runner{}
		err := redactr.Exec(runner)
		if err != nil {
			t.Errorf("Exec() got err: %v", err)
			return
		}
	})

	t.Run("if the runner fails, it should return an error", func(t *testing.T) {
		runner := &fakes.Runner{}
		runner.RunReturns(fmt.Errorf("all is lost"))
		err := redactr.Exec(runner)
		if err == nil || !strings.Contains(err.Error(), "all is lost") {
			t.Errorf(`Exec(): expected error with "all is lost", got: %v`, err)
			return
		}
	})

	t.Run("when called with the StopIfEnvChanges option, it should stop the command when the running configuration has changed", func(t *testing.T) {
		runner := &fakes.Runner{}

		stop := make(chan struct{})
		runner.RunStub = func() error {
			timeout := time.After(1 * time.Second)
			select {
			case <-timeout:
				return fmt.Errorf("timeout")
			case <-stop:
				return nil
			}
		}
		runner.StopStub = func() {
			stop <- struct{}{}
		}
		runner.HasConfigurationChangedReturns(true, nil)

		err := redactr.Exec(runner, redactr.StopIfEnvChanges(100*time.Millisecond))
		if err != nil {
			t.Errorf("Exec() got err: %v", err)
			return
		}
		if runner.RunCallCount() != 1 {
			t.Errorf("Exec() expected Run() to be called one time, got %v", runner.RunCallCount())
			return
		}
		if runner.StopCallCount() != 1 {
			t.Errorf("Exec() expected Stop() to be called one time, got %v", runner.StopCallCount())
			return
		}
	})

	t.Run("when called with the RestartIfEnvChanges option, it should restart the command when the running configuration has changed", func(t *testing.T) {
		runner := &fakes.Runner{}

		restart := make(chan struct{})
		runner.RunStub = func() error {
			i := 0
			timeout := time.After(10 * time.Second)
			for {
				if i > 4 {
					return nil // exit normally after 4 restarts
				}

				select {
				case <-timeout:
					return fmt.Errorf("timeout")
				case <-restart:
					i++
				}
			}
		}
		runner.RestartStub = func() {
			restart <- struct{}{}
		}
		runner.HasConfigurationChangedReturns(true, nil)

		err := redactr.Exec(runner, redactr.RestartIfEnvChanges(100*time.Millisecond))
		if err != nil {
			t.Errorf("Exec() got err: %v", err)
			return
		}
		if runner.RunCallCount() != 1 {
			t.Errorf("Exec() expected Run() to be called one time, got %v", runner.RunCallCount())
			return
		}
		if runner.RestartCallCount() != 5 {
			t.Errorf("Exec() expected Restart() to be called 5 times, got %v", runner.RestartCallCount())
			return
		}
	})
}
