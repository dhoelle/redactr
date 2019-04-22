// Code generated by counterfeiter. DO NOT EDIT.
package fakes

import (
	"sync"

	"github.com/dhoelle/redactr"
)

type TokenWrapper struct {
	WrapTokenStub        func(string, string, string) string
	wrapTokenMutex       sync.RWMutex
	wrapTokenArgsForCall []struct {
		arg1 string
		arg2 string
		arg3 string
	}
	wrapTokenReturns struct {
		result1 string
	}
	wrapTokenReturnsOnCall map[int]struct {
		result1 string
	}
	invocations      map[string][][]interface{}
	invocationsMutex sync.RWMutex
}

func (fake *TokenWrapper) WrapToken(arg1 string, arg2 string, arg3 string) string {
	fake.wrapTokenMutex.Lock()
	ret, specificReturn := fake.wrapTokenReturnsOnCall[len(fake.wrapTokenArgsForCall)]
	fake.wrapTokenArgsForCall = append(fake.wrapTokenArgsForCall, struct {
		arg1 string
		arg2 string
		arg3 string
	}{arg1, arg2, arg3})
	fake.recordInvocation("WrapToken", []interface{}{arg1, arg2, arg3})
	fake.wrapTokenMutex.Unlock()
	if fake.WrapTokenStub != nil {
		return fake.WrapTokenStub(arg1, arg2, arg3)
	}
	if specificReturn {
		return ret.result1
	}
	fakeReturns := fake.wrapTokenReturns
	return fakeReturns.result1
}

func (fake *TokenWrapper) WrapTokenCallCount() int {
	fake.wrapTokenMutex.RLock()
	defer fake.wrapTokenMutex.RUnlock()
	return len(fake.wrapTokenArgsForCall)
}

func (fake *TokenWrapper) WrapTokenCalls(stub func(string, string, string) string) {
	fake.wrapTokenMutex.Lock()
	defer fake.wrapTokenMutex.Unlock()
	fake.WrapTokenStub = stub
}

func (fake *TokenWrapper) WrapTokenArgsForCall(i int) (string, string, string) {
	fake.wrapTokenMutex.RLock()
	defer fake.wrapTokenMutex.RUnlock()
	argsForCall := fake.wrapTokenArgsForCall[i]
	return argsForCall.arg1, argsForCall.arg2, argsForCall.arg3
}

func (fake *TokenWrapper) WrapTokenReturns(result1 string) {
	fake.wrapTokenMutex.Lock()
	defer fake.wrapTokenMutex.Unlock()
	fake.WrapTokenStub = nil
	fake.wrapTokenReturns = struct {
		result1 string
	}{result1}
}

func (fake *TokenWrapper) WrapTokenReturnsOnCall(i int, result1 string) {
	fake.wrapTokenMutex.Lock()
	defer fake.wrapTokenMutex.Unlock()
	fake.WrapTokenStub = nil
	if fake.wrapTokenReturnsOnCall == nil {
		fake.wrapTokenReturnsOnCall = make(map[int]struct {
			result1 string
		})
	}
	fake.wrapTokenReturnsOnCall[i] = struct {
		result1 string
	}{result1}
}

func (fake *TokenWrapper) Invocations() map[string][][]interface{} {
	fake.invocationsMutex.RLock()
	defer fake.invocationsMutex.RUnlock()
	fake.wrapTokenMutex.RLock()
	defer fake.wrapTokenMutex.RUnlock()
	copiedInvocations := map[string][][]interface{}{}
	for key, value := range fake.invocations {
		copiedInvocations[key] = value
	}
	return copiedInvocations
}

func (fake *TokenWrapper) recordInvocation(key string, args []interface{}) {
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

var _ redactr.TokenWrapper = new(TokenWrapper)
