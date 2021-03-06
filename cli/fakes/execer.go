// Code generated by counterfeiter. DO NOT EDIT.
package fakes

import (
	"sync"

	"github.com/dhoelle/redactr"
	"github.com/dhoelle/redactr/cli"
)

type Execer struct {
	ExecStub        func(string, []string, ...redactr.ExecOption) error
	execMutex       sync.RWMutex
	execArgsForCall []struct {
		arg1 string
		arg2 []string
		arg3 []redactr.ExecOption
	}
	execReturns struct {
		result1 error
	}
	execReturnsOnCall map[int]struct {
		result1 error
	}
	invocations      map[string][][]interface{}
	invocationsMutex sync.RWMutex
}

func (fake *Execer) Exec(arg1 string, arg2 []string, arg3 ...redactr.ExecOption) error {
	var arg2Copy []string
	if arg2 != nil {
		arg2Copy = make([]string, len(arg2))
		copy(arg2Copy, arg2)
	}
	fake.execMutex.Lock()
	ret, specificReturn := fake.execReturnsOnCall[len(fake.execArgsForCall)]
	fake.execArgsForCall = append(fake.execArgsForCall, struct {
		arg1 string
		arg2 []string
		arg3 []redactr.ExecOption
	}{arg1, arg2Copy, arg3})
	fake.recordInvocation("Exec", []interface{}{arg1, arg2Copy, arg3})
	fake.execMutex.Unlock()
	if fake.ExecStub != nil {
		return fake.ExecStub(arg1, arg2, arg3...)
	}
	if specificReturn {
		return ret.result1
	}
	fakeReturns := fake.execReturns
	return fakeReturns.result1
}

func (fake *Execer) ExecCallCount() int {
	fake.execMutex.RLock()
	defer fake.execMutex.RUnlock()
	return len(fake.execArgsForCall)
}

func (fake *Execer) ExecCalls(stub func(string, []string, ...redactr.ExecOption) error) {
	fake.execMutex.Lock()
	defer fake.execMutex.Unlock()
	fake.ExecStub = stub
}

func (fake *Execer) ExecArgsForCall(i int) (string, []string, []redactr.ExecOption) {
	fake.execMutex.RLock()
	defer fake.execMutex.RUnlock()
	argsForCall := fake.execArgsForCall[i]
	return argsForCall.arg1, argsForCall.arg2, argsForCall.arg3
}

func (fake *Execer) ExecReturns(result1 error) {
	fake.execMutex.Lock()
	defer fake.execMutex.Unlock()
	fake.ExecStub = nil
	fake.execReturns = struct {
		result1 error
	}{result1}
}

func (fake *Execer) ExecReturnsOnCall(i int, result1 error) {
	fake.execMutex.Lock()
	defer fake.execMutex.Unlock()
	fake.ExecStub = nil
	if fake.execReturnsOnCall == nil {
		fake.execReturnsOnCall = make(map[int]struct {
			result1 error
		})
	}
	fake.execReturnsOnCall[i] = struct {
		result1 error
	}{result1}
}

func (fake *Execer) Invocations() map[string][][]interface{} {
	fake.invocationsMutex.RLock()
	defer fake.invocationsMutex.RUnlock()
	fake.execMutex.RLock()
	defer fake.execMutex.RUnlock()
	copiedInvocations := map[string][][]interface{}{}
	for key, value := range fake.invocations {
		copiedInvocations[key] = value
	}
	return copiedInvocations
}

func (fake *Execer) recordInvocation(key string, args []interface{}) {
	fake.invocationsMutex.Lock()
	defer fake.invocationsMutex.Unlock()
	if fake.invocations == nil {
		fake.invocations = map[string][][]interface{}{}
	}
	if fake.invocations[key] == nil {
		fake.invocations[key] = [][]interface{}{}
	}
	fake.invocations[key] = append(fake.invocations[key], args)
}

var _ cli.Execer = new(Execer)
