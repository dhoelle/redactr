// Code generated by counterfeiter. DO NOT EDIT.
package fakes

import (
	"sync"

	"github.com/dhoelle/redactr"
)

type TokenLocator struct {
	LocateTokensStub func(string) ([]struct {
		EnvelopeStart int
		PayloadStart  int
		PayloadEnd    int
		EnvelopeEnd   int
	}, error)
	locateTokensMutex       sync.RWMutex
	locateTokensArgsForCall []struct {
		arg1 string
	}
	locateTokensReturns struct {
		result1 []struct {
			EnvelopeStart int
			PayloadStart  int
			PayloadEnd    int
			EnvelopeEnd   int
		}
		result2 error
	}
	locateTokensReturnsOnCall map[int]struct {
		result1 []struct {
			EnvelopeStart int
			PayloadStart  int
			PayloadEnd    int
			EnvelopeEnd   int
		}
		result2 error
	}
	invocations      map[string][][]interface{}
	invocationsMutex sync.RWMutex
}

func (fake *TokenLocator) LocateTokens(arg1 string) ([]struct {
	EnvelopeStart int
	PayloadStart  int
	PayloadEnd    int
	EnvelopeEnd   int
}, error) {
	fake.locateTokensMutex.Lock()
	ret, specificReturn := fake.locateTokensReturnsOnCall[len(fake.locateTokensArgsForCall)]
	fake.locateTokensArgsForCall = append(fake.locateTokensArgsForCall, struct {
		arg1 string
	}{arg1})
	fake.recordInvocation("LocateTokens", []interface{}{arg1})
	fake.locateTokensMutex.Unlock()
	if fake.LocateTokensStub != nil {
		return fake.LocateTokensStub(arg1)
	}
	if specificReturn {
		return ret.result1, ret.result2
	}
	fakeReturns := fake.locateTokensReturns
	return fakeReturns.result1, fakeReturns.result2
}

func (fake *TokenLocator) LocateTokensCallCount() int {
	fake.locateTokensMutex.RLock()
	defer fake.locateTokensMutex.RUnlock()
	return len(fake.locateTokensArgsForCall)
}

func (fake *TokenLocator) LocateTokensCalls(stub func(string) ([]struct {
	EnvelopeStart int
	PayloadStart  int
	PayloadEnd    int
	EnvelopeEnd   int
}, error)) {
	fake.locateTokensMutex.Lock()
	defer fake.locateTokensMutex.Unlock()
	fake.LocateTokensStub = stub
}

func (fake *TokenLocator) LocateTokensArgsForCall(i int) string {
	fake.locateTokensMutex.RLock()
	defer fake.locateTokensMutex.RUnlock()
	argsForCall := fake.locateTokensArgsForCall[i]
	return argsForCall.arg1
}

func (fake *TokenLocator) LocateTokensReturns(result1 []struct {
	EnvelopeStart int
	PayloadStart  int
	PayloadEnd    int
	EnvelopeEnd   int
}, result2 error) {
	fake.locateTokensMutex.Lock()
	defer fake.locateTokensMutex.Unlock()
	fake.LocateTokensStub = nil
	fake.locateTokensReturns = struct {
		result1 []struct {
			EnvelopeStart int
			PayloadStart  int
			PayloadEnd    int
			EnvelopeEnd   int
		}
		result2 error
	}{result1, result2}
}

func (fake *TokenLocator) LocateTokensReturnsOnCall(i int, result1 []struct {
	EnvelopeStart int
	PayloadStart  int
	PayloadEnd    int
	EnvelopeEnd   int
}, result2 error) {
	fake.locateTokensMutex.Lock()
	defer fake.locateTokensMutex.Unlock()
	fake.LocateTokensStub = nil
	if fake.locateTokensReturnsOnCall == nil {
		fake.locateTokensReturnsOnCall = make(map[int]struct {
			result1 []struct {
				EnvelopeStart int
				PayloadStart  int
				PayloadEnd    int
				EnvelopeEnd   int
			}
			result2 error
		})
	}
	fake.locateTokensReturnsOnCall[i] = struct {
		result1 []struct {
			EnvelopeStart int
			PayloadStart  int
			PayloadEnd    int
			EnvelopeEnd   int
		}
		result2 error
	}{result1, result2}
}

func (fake *TokenLocator) Invocations() map[string][][]interface{} {
	fake.invocationsMutex.RLock()
	defer fake.invocationsMutex.RUnlock()
	fake.locateTokensMutex.RLock()
	defer fake.locateTokensMutex.RUnlock()
	copiedInvocations := map[string][][]interface{}{}
	for key, value := range fake.invocations {
		copiedInvocations[key] = value
	}
	return copiedInvocations
}

func (fake *TokenLocator) recordInvocation(key string, args []interface{}) {
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

var _ redactr.TokenLocator = new(TokenLocator)
