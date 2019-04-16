package cryptr

import (
	"regexp"
	"testing"

	"github.com/dhoelle/cryptr/crypto"
)

// Test that we can encrypt all secrets embedded in a
// plaintext, then decrypt back to the plaintext
func Test_Encrypt_Decrypt(t *testing.T) {
	tests := []struct {
		name           string
		plaintext      string
		containsSecret bool
		wantMixed      string // a regex that the mixed plaintext/ciphertext should match
		wantStrip      string
		wantErr        bool
	}{
		{
			name:      "empty string",
			plaintext: "",
			wantMixed: "^$",
			wantStrip: "",
		},
		{
			name:           "simple",
			plaintext:      "hello secret:foo:secret secret:bar:secret world",
			containsSecret: true,
			wantMixed:      "^hello secret-encrypted:[A-Za-z0-9+/]+=*:secret-encrypted secret-encrypted:[A-Za-z0-9+/]+=*:secret-encrypted world$",
			wantStrip:      "hello foo bar world",
		},
		{
			name:      "no secrets",
			plaintext: "hello world",
			wantMixed: "^hello world$",
			wantStrip: "hello world",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			key1, err := crypto.NewEncryptionKey()
			if err != nil {
				t.Errorf("could not generate random encryption key for test: %v", err)
				return
			}

			key2, err := crypto.NewEncryptionKey()
			if err != nil {
				t.Errorf("could not generate random encryption key for test: %v", err)
				return
			}

			mixed, err := Encrypt(tt.plaintext, key1)
			if err != nil {
				t.Errorf("Encrypt() error = %v", err)
				return
			}

			// confirm that the mixed text is modified as we'd expect
			if tt.wantMixed != "" {
				re := regexp.MustCompile(tt.wantMixed)
				if !re.MatchString(mixed) {
					t.Errorf("Encrypt() mixed plaintext/ciphertext doesn't match regex\n\tregex: %v\n\t  got: %v", tt.wantMixed, mixed)
					return
				}
			}

			// confirm that the plaintext decrypts correctly
			plaintext, err := Decrypt(mixed, key1, false)
			if err != nil {
				t.Errorf("Decrypt() error = %v", err)
				return
			}

			if plaintext != tt.plaintext {
				t.Errorf("Decrypted plaintext does not match input\n\t    input: %v\n\tdecrypted: %v", tt.plaintext, plaintext)
				return
			}

			// confirm that, if the plaintext contained secrets,
			// it does not decrypt properly with a different key
			if tt.containsSecret {
				badKeyPT, err := Decrypt(mixed, key2, false)
				if err == nil || badKeyPT == tt.plaintext {
					t.Errorf("Decrypt() bad key case: expected error, got = %v", err)
					return
				}
			}

			// confirm that stripped plaintext decrypts correctly
			if tt.wantStrip != "" {
				strippedPT, err := Decrypt(mixed, key1, true)
				if err != nil {
					t.Errorf("Decrypt() error = %v", err)
					return
				}

				if strippedPT != tt.wantStrip {
					t.Errorf("Decrypted-and-stripped plaintext does not match\n\twant: %v\n\t got: %v", tt.wantStrip, strippedPT)
					return
				}
			}
		})
	}
}

// func Test_Encrypt(t *testing.T) {
// 	key1 := &[32]byte{1, 1, 1, 1, 2, 2, 2, 2, 3, 3, 3, 3, 4, 4, 4, 4, 5, 5, 5, 5, 6, 6, 6, 6, 7, 7, 7, 7, 8, 8, 8, 8}

// 	// key1, err := crypto.NewEncryptionKey()
// 	// if err != nil {
// 	// 	t.Errorf("could not generate random encryption key for test: %v", err)
// 	// 	return
// 	// }

// 	type args struct {
// 		plaintext string
// 		key       *[32]byte
// 	}
// 	tests := []struct {
// 		name    string
// 		args    args
// 		want    string
// 		wantErr bool
// 	}{
// 		{
// 			name: "simple",
// 			args: args{key: key1, plaintext: "hello secret:foo:secret secret:bar:secret world"},
// 			want: "hello secret-encrypted:Zm9v:secret-encrypted secret-encrypted:YmFy:secret-encrypted world",
// 		},
// 		{
// 			name: "missing key, but no secrets",
// 			args: args{key: key1, plaintext: "hello world"},
// 			want: "hello world",
// 		},
// 		{
// 			name:    "missing key and secrets found",
// 			args:    args{key: key1, plaintext: "hello secret:foo:secret world"},
// 			wantErr: true,
// 		},
// 		{
// 			name: "it shouldn't encrypt secrets that have already been encrypted",
// 			args: args{key: key1, plaintext: "hello secret-encrypted:Zm9v:secret-encrypted secret-encrypted:YmFy:secret-encrypted world"},
// 			want: "hello secret-encrypted:Zm9v:secret-encrypted secret-encrypted:YmFy:secret-encrypted world",
// 		},
// 	}
// 	for _, tt := range tests {
// 		t.Run(tt.name, func(t *testing.T) {
// 			got, err := Encrypt(tt.args.plaintext, tt.args.key)
// 			if (err != nil) != tt.wantErr {
// 				t.Errorf("Encrypt() error = %v, wantErr %v", err, tt.wantErr)
// 				return
// 			}

// 			if got != tt.want {
// 				t.Errorf("Encrypt() = %s, want %s", got, tt.want)
// 			}
// 		})
// 	}
// }

func TestDecrypt(t *testing.T) {
	key1 := &[32]byte{1, 1, 1, 1, 2, 2, 2, 2, 3, 3, 3, 3, 4, 4, 4, 4, 5, 5, 5, 5, 6, 6, 6, 6, 7, 7, 7, 7, 8, 8, 8, 8}

	type args struct {
		s     string
		key   *[32]byte
		strip bool
	}
	tests := []struct {
		name    string
		args    args
		want    string
		wantErr bool
	}{
		{
			name: "simple",
			args: args{
				key: key1,
				s:   "hello secret-encrypted:BZlAy+JrpR0mFGFYtiVP5BqbZvp4KWO81D2E/iGo9A==:secret-encrypted secret-encrypted:ipLIhq2mQERSnCmNuJd+1/0jtApxPnW/QOm2P0VRZQ==:secret-encrypted world",
			},
			want: "hello secret:foo:secret secret:bar:secret world",
		},
		{
			name: "simple, stripped",
			args: args{
				key:   key1,
				s:     "hello secret-encrypted:BZlAy+JrpR0mFGFYtiVP5BqbZvp4KWO81D2E/iGo9A==:secret-encrypted secret-encrypted:ipLIhq2mQERSnCmNuJd+1/0jtApxPnW/QOm2P0VRZQ==:secret-encrypted world",
				strip: true,
			},
			want: "hello foo bar world",
		},
		{
			name: "missing key, but no secrets",
			args: args{key: nil, s: "hello world"},
			want: "hello world",
		},
		{
			name: "missing key and secrets found",
			args: args{
				key: nil,
				s:   "hello secret-encrypted:Zm9v:secret-encrypted secret-encrypted:YmFy:secret-encrypted world",
			},
			wantErr: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := Decrypt(tt.args.s, tt.args.key, tt.args.strip)
			if (err != nil) != tt.wantErr {
				t.Errorf("Decrypt() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if got != tt.want {
				t.Errorf("Decrypt() = %v, want %v", got, tt.want)
			}
		})
	}
}

// func Test_insertBytes(t *testing.T) {
// 	type args struct {
// 		dest []byte
// 		new  []byte
// 		i    int
// 	}
// 	tests := []struct {
// 		name    string
// 		args    args
// 		want    []byte
// 		wantErr bool
// 	}{
// 		{
// 			name: "insert into nil",
// 			args: args{
// 				dest: nil,
// 				new:  []byte("foo"),
// 				i:    0,
// 			},
// 			want: []byte("foo"),
// 		},
// 		{
// 			name: "insert at beginning",
// 			args: args{
// 				dest: []byte("world"),
// 				new:  []byte("hello "),
// 				i:    0,
// 			},
// 			want: []byte("hello world"),
// 		},
// 		{
// 			name: "insert in middle",
// 			args: args{
// 				dest: []byte("helrld"),
// 				new:  []byte("lo wo"),
// 				i:    3,
// 			},
// 			want: []byte("hello world"),
// 		},
// 		{
// 			name: "insert at end",
// 			args: args{
// 				dest: []byte("hello"),
// 				new:  []byte(" world"),
// 				i:    5,
// 			},
// 			want: []byte("hello world"),
// 		},
// 		{
// 			name: "insert past end",
// 			args: args{
// 				dest: []byte("hello"),
// 				new:  []byte(" world"),
// 				i:    6,
// 			},
// 			wantErr: true,
// 		},
// 	}
// 	for _, tt := range tests {
// 		t.Run(tt.name, func(t *testing.T) {
// 			insertBytes(tt.args.dest, tt.args.new, tt.args.i)
// 			if (err != nil) != tt.wantErr {
// 				t.Errorf("Decrypt() error = %v, wantErr %v", err, tt.wantErr)
// 				return
// 			}
// 			if got != tt.want {
// 				t.Errorf("Decrypt() = %v, want %v", got, tt.want)
// 			}

// 		})
// 	}
// }
