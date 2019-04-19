package aes

import (
	"regexp"
	"testing"
)

func TestEncoding_Encode(t *testing.T) {
	type fields struct {
		Key *[32]byte
	}
	type args struct {
		s string
	}
	tests := []struct {
		name         string
		fields       fields
		args         args
		wantErr      bool
		wantCiphered string // a regex that the ciphertext should match
	}{
		{
			name: "simple",
			fields: fields{
				Key: &[32]byte{1, 1, 1, 1, 2, 2, 2, 2, 3, 3, 3, 3, 4, 4, 4, 4, 5, 5, 5, 5, 6, 6, 6, 6, 7, 7, 7, 7, 8, 8, 8, 8},
			},
			args:         args{s: "hunter2"},
			wantCiphered: `^(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?$`, // base64
		},
		{
			name:    "missing key",
			args:    args{s: "foo"},
			wantErr: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			e := &Encoding{
				Key: tt.fields.Key,
			}
			got, err := e.Encode(tt.args.s)
			if (err != nil) != tt.wantErr {
				t.Errorf("Encoding.Encode() error = %v, wantErr %v", err, tt.wantErr)
				return
			}

			if tt.wantCiphered != "" {
				re := regexp.MustCompile(tt.wantCiphered)
				if !re.MatchString(got) {
					t.Errorf("Encoding.Encode()ciphertext doesn't match regex\n\tregex: %v\n\t  got: %v", tt.wantCiphered, got)
					return
				}
			}
		})
	}
}

func TestEncoding_Decode(t *testing.T) {
	type fields struct {
		Key *[32]byte
	}
	type args struct {
		s string
	}
	tests := []struct {
		name    string
		fields  fields
		args    args
		want    string
		wantErr bool
	}{
		{
			name: "simple",
			fields: fields{
				Key: &[32]byte{1, 1, 1, 1, 2, 2, 2, 2, 3, 3, 3, 3, 4, 4, 4, 4, 5, 5, 5, 5, 6, 6, 6, 6, 7, 7, 7, 7, 8, 8, 8, 8},
			},
			args: args{s: "KHnpT8YvbfqjsxIiAmRQ54EDDe6tjBtZi24/YqNyTVxwp8E="},
			want: "hunter2",
		},
		{
			name:    "missing key",
			args:    args{s: "foo"},
			wantErr: true,
		},
		{
			name: "cipher is not base64 encrypted",
			fields: fields{
				Key: &[32]byte{1, 1, 1, 1, 2, 2, 2, 2, 3, 3, 3, 3, 4, 4, 4, 4, 5, 5, 5, 5, 6, 6, 6, 6, 7, 7, 7, 7, 8, 8, 8, 8},
			},
			args:    args{s: "not a base64 string"},
			wantErr: true,
		},
		{
			name: "key does not match",
			fields: fields{
				Key: &[32]byte{42, 42, 42, 42, 2, 2, 2, 2, 3, 3, 3, 3, 4, 4, 4, 4, 5, 5, 5, 5, 6, 6, 6, 6, 7, 7, 7, 7, 8, 8, 8, 8},
			},
			args:    args{s: "KHnpT8YvbfqjsxIiAmRQ54EDDe6tjBtZi24/YqNyTVxwp8E="},
			wantErr: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			e := &Encoding{
				Key: tt.fields.Key,
			}
			got, err := e.Decode(tt.args.s)
			if (err != nil) != tt.wantErr {
				t.Errorf("Encoding.Decode() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if got != tt.want {
				t.Errorf("Encoding.Decode() = %v, want %v", got, tt.want)
			}
		})
	}
}
