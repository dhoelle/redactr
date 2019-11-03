// Code generated by counterfeiter. DO NOT EDIT.
package fakes

import (
	"sync"

	"github.com/dhoelle/redactr/exec"
)

type Replacer struct {
	ReplaceStub        func(string) (string, error)
	replaceMutex       sync.RWMutex
	replaceArgsForCall []struct {
		arg1 string
	}
	replaceReturns struct {
		result1 string
		result2 error
	}
	replaceReturnsOnCall map[int]struct {
		result1 string
		result2 error
	}
	invocations      map[string][][]interface{}
	invocationsMutex sync.RWMutex
}

func (fake *Replacer) Replace(arg1 string) (string, error) {
	fake.replaceMutex.Lock()
	ret, specificReturn := fake.replaceReturnsOnCall[len(fake.replaceArgsForCall)]
	fake.replaceArgsForCall = append(fake.replaceArgsForCall, struct {
		arg1 string
	}{arg1})
	fake.recordInvocation("Replace", []interface{}{arg1})
	fake.replaceMutex.Unlock()
	if fake.ReplaceStub != nil {
		return fake.ReplaceStub(arg1)
	}
	if specificReturn {
		return ret.result1, ret.result2
	}
	fakeReturns := fake.replaceReturns
	return fakeReturns.result1, fakeReturns.result2
}

func (fake *Replacer) ReplaceCallCount() int {
	fake.replaceMutex.RLock()
	defer fake.replaceMutex.RUnlock()
	return len(fake.replaceArgsForCall)
}

func (fake *Replacer) ReplaceCalls(stub func(string) (string, error)) {
	fake.replaceMutex.Lock()
	defer fake.replaceMutex.Unlock()
	fake.ReplaceStub = stub
}

func (fake *Replacer) ReplaceArgsForCall(i int) string {
	fake.replaceMutex.RLock()
	defer fake.replaceMutex.RUnlock()
	argsForCall := fake.replaceArgsForCall[i]
	return argsForCall.arg1
}

func (fake *Replacer) ReplaceReturns(result1 string, result2 error) {
	fake.replaceMutex.Lock()
	defer fake.replaceMutex.Unlock()
	fake.ReplaceStub = nil
	fake.replaceReturns = struct {
		result1 string
		result2 error
	}{result1, result2}
}

func (fake *Replacer) ReplaceReturnsOnCall(i int, result1 string, result2 error) {
	fake.replaceMutex.Lock()
	defer fake.replaceMutex.Unlock()
	fake.ReplaceStub = nil
	if fake.replaceReturnsOnCall == nil {
		fake.replaceReturnsOnCall = make(map[int]struct {
			result1 string
			result2 error
		})
	}
	fake.replaceReturnsOnCall[i] = struct {
		result1 string
		result2 error
	}{result1, result2}
}

func (fake *Replacer) Invocations() map[string][][]interface{} {
	fake.invocationsMutex.RLock()
	defer fake.invocationsMutex.RUnlock()
	fake.replaceMutex.RLock()
	defer fake.replaceMutex.RUnlock()
	copiedInvocations := map[string][][]interface{}{}
	for key, value := range fake.invocations {
		copiedInvocations[key] = value
	}
	return copiedInvocations
}

func (fake *Replacer) recordInvocation(key string, args []interface{}) {
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

var _ exec.Replacer = new(Replacer)