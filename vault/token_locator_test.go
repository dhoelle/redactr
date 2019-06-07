package vault_test

import (
	"reflect"
	"testing"

	"github.com/dhoelle/redactr/vault"
)

func Test_RedactedRE(t *testing.T) {
	type args struct {
		s string
	}
	tests := []struct {
		name          string
		args          args
		wantEnvelopes []string
		wantPayloads  []string
	}{
		{
			name:          "simple",
			args:          args{s: "vault:foo/bar#baz"},
			wantEnvelopes: []string{"vault:foo/bar#baz"},
			wantPayloads:  []string{"foo/bar#baz"},
		},
		{
			name:          "find multiple tokens",
			args:          args{s: "asdf   vault:foo/bar#baz   vault:a/b/c#d ZZZ123!"},
			wantEnvelopes: []string{"vault:foo/bar#baz", "vault:a/b/c#d"},
			wantPayloads:  []string{"foo/bar#baz", "a/b/c#d"},
		},
		{
			name:          "find tokens within json strings",
			args:          args{s: `{"foo": "vault:foo/bar#baz"}`},
			wantEnvelopes: []string{"vault:foo/bar#baz"},
			wantPayloads:  []string{"foo/bar#baz"},
		},
		{
			name:          "find tokens inside single-quoted strings",
			args:          args{s: `'vault:foo/bar#baz'`},
			wantEnvelopes: []string{"vault:foo/bar#baz"},
			wantPayloads:  []string{"foo/bar#baz"},
		},
		{
			name: "ignore tokens without a key",
			args: args{s: "vault:foo/bar"},
		},
		{
			name: "ignore tokens without a path",
			args: args{s: "vault:#baz"},
		},
		{
			name: "ignore tokens which span newlines",
			args: args{s: "zzzvault:foo/bar/\n#baz"},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var envelopes []string
			var payloads []string
			matches := vault.RedactedRE.FindAllStringSubmatch(tt.args.s, -1)
			for _, m := range matches {
				if len(m) > 0 {
					envelopes = append(envelopes, m[0])
				}
				if len(m) > 1 {
					payloads = append(payloads, m[1])
				}
			}

			if !reflect.DeepEqual(tt.wantEnvelopes, envelopes) {
				t.Errorf("Vault Token RE: want envelopes = %v, got %v", tt.wantEnvelopes, envelopes)
				return
			}

			if !reflect.DeepEqual(tt.wantPayloads, payloads) {
				t.Errorf("Vault Token RE: want payloads = %v, got %v", tt.wantPayloads, payloads)
				return
			}
		})
	}
}
