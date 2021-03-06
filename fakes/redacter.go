// Code generated by counterfeiter. DO NOT EDIT.
package fakes

import (
	"sync"

	"github.com/dhoelle/redactr"
)

type Redacter struct {
	RedactStub        func(string) (string, error)
	redactMutex       sync.RWMutex
	redactArgsForCall []struct {
		arg1 string
	}
	redactReturns struct {
		result1 string
		result2 error
	}
	redactReturnsOnCall map[int]struct {
		result1 string
		result2 error
	}
	invocations      map[string][][]interface{}
	invocationsMutex sync.RWMutex
}

func (fake *Redacter) Redact(arg1 string) (string, error) {
	fake.redactMutex.Lock()
	ret, specificReturn := fake.redactReturnsOnCall[len(fake.redactArgsForCall)]
	fake.redactArgsForCall = append(fake.redactArgsForCall, struct {
		arg1 string
	}{arg1})
	fake.recordInvocation("Redact", []interface{}{arg1})
	fake.redactMutex.Unlock()
	if fake.RedactStub != nil {
		return fake.RedactStub(arg1)
	}
	if specificReturn {
		return ret.result1, ret.result2
	}
	fakeReturns := fake.redactReturns
	return fakeReturns.result1, fakeReturns.result2
}

func (fake *Redacter) RedactCallCount() int {
	fake.redactMutex.RLock()
	defer fake.redactMutex.RUnlock()
	return len(fake.redactArgsForCall)
}

func (fake *Redacter) RedactCalls(stub func(string) (string, error)) {
	fake.redactMutex.Lock()
	defer fake.redactMutex.Unlock()
	fake.RedactStub = stub
}

func (fake *Redacter) RedactArgsForCall(i int) string {
	fake.redactMutex.RLock()
	defer fake.redactMutex.RUnlock()
	argsForCall := fake.redactArgsForCall[i]
	return argsForCall.arg1
}

func (fake *Redacter) RedactReturns(result1 string, result2 error) {
	fake.redactMutex.Lock()
	defer fake.redactMutex.Unlock()
	fake.RedactStub = nil
	fake.redactReturns = struct {
		result1 string
		result2 error
	}{result1, result2}
}

func (fake *Redacter) RedactReturnsOnCall(i int, result1 string, result2 error) {
	fake.redactMutex.Lock()
	defer fake.redactMutex.Unlock()
	fake.RedactStub = nil
	if fake.redactReturnsOnCall == nil {
		fake.redactReturnsOnCall = make(map[int]struct {
			result1 string
			result2 error
		})
	}
	fake.redactReturnsOnCall[i] = struct {
		result1 string
		result2 error
	}{result1, result2}
}

func (fake *Redacter) Invocations() map[string][][]interface{} {
	fake.invocationsMutex.RLock()
	defer fake.invocationsMutex.RUnlock()
	fake.redactMutex.RLock()
	defer fake.redactMutex.RUnlock()
	copiedInvocations := map[string][][]interface{}{}
	for key, value := range fake.invocations {
		copiedInvocations[key] = value
	}
	return copiedInvocations
}

func (fake *Redacter) recordInvocation(key string, args []interface{}) {
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

var _ redactr.Redacter = new(Redacter)
