// Code generated by counterfeiter. DO NOT EDIT.
package fakes

import (
	"sync"

	"github.com/dhoelle/redactr"
)

type TokenRedacter struct {
	RedactTokensStub        func(string) (string, error)
	redactTokensMutex       sync.RWMutex
	redactTokensArgsForCall []struct {
		arg1 string
	}
	redactTokensReturns struct {
		result1 string
		result2 error
	}
	redactTokensReturnsOnCall map[int]struct {
		result1 string
		result2 error
	}
	invocations      map[string][][]interface{}
	invocationsMutex sync.RWMutex
}

func (fake *TokenRedacter) RedactTokens(arg1 string) (string, error) {
	fake.redactTokensMutex.Lock()
	ret, specificReturn := fake.redactTokensReturnsOnCall[len(fake.redactTokensArgsForCall)]
	fake.redactTokensArgsForCall = append(fake.redactTokensArgsForCall, struct {
		arg1 string
	}{arg1})
	fake.recordInvocation("RedactTokens", []interface{}{arg1})
	fake.redactTokensMutex.Unlock()
	if fake.RedactTokensStub != nil {
		return fake.RedactTokensStub(arg1)
	}
	if specificReturn {
		return ret.result1, ret.result2
	}
	fakeReturns := fake.redactTokensReturns
	return fakeReturns.result1, fakeReturns.result2
}

func (fake *TokenRedacter) RedactTokensCallCount() int {
	fake.redactTokensMutex.RLock()
	defer fake.redactTokensMutex.RUnlock()
	return len(fake.redactTokensArgsForCall)
}

func (fake *TokenRedacter) RedactTokensCalls(stub func(string) (string, error)) {
	fake.redactTokensMutex.Lock()
	defer fake.redactTokensMutex.Unlock()
	fake.RedactTokensStub = stub
}

func (fake *TokenRedacter) RedactTokensArgsForCall(i int) string {
	fake.redactTokensMutex.RLock()
	defer fake.redactTokensMutex.RUnlock()
	argsForCall := fake.redactTokensArgsForCall[i]
	return argsForCall.arg1
}

func (fake *TokenRedacter) RedactTokensReturns(result1 string, result2 error) {
	fake.redactTokensMutex.Lock()
	defer fake.redactTokensMutex.Unlock()
	fake.RedactTokensStub = nil
	fake.redactTokensReturns = struct {
		result1 string
		result2 error
	}{result1, result2}
}

func (fake *TokenRedacter) RedactTokensReturnsOnCall(i int, result1 string, result2 error) {
	fake.redactTokensMutex.Lock()
	defer fake.redactTokensMutex.Unlock()
	fake.RedactTokensStub = nil
	if fake.redactTokensReturnsOnCall == nil {
		fake.redactTokensReturnsOnCall = make(map[int]struct {
			result1 string
			result2 error
		})
	}
	fake.redactTokensReturnsOnCall[i] = struct {
		result1 string
		result2 error
	}{result1, result2}
}

func (fake *TokenRedacter) Invocations() map[string][][]interface{} {
	fake.invocationsMutex.RLock()
	defer fake.invocationsMutex.RUnlock()
	fake.redactTokensMutex.RLock()
	defer fake.redactTokensMutex.RUnlock()
	copiedInvocations := map[string][][]interface{}{}
	for key, value := range fake.invocations {
		copiedInvocations[key] = value
	}
	return copiedInvocations
}

func (fake *TokenRedacter) recordInvocation(key string, args []interface{}) {
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

var _ redactr.TokenRedacter = new(TokenRedacter)
