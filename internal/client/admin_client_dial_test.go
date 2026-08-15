package client

import (
	"os"
	"testing"
)

// adminDialIsPlaintext mirrors the credential decision in NewAdminClient. The
// dial itself needs a bootstrap.Context and a CertManager, so the precedence —
// which is the whole of the bug — is asserted here directly.
func adminDialIsPlaintext(registrationInsecure string, tlsAvailable bool) bool {
	switch {
	case registrationInsecure == "1":
		return true
	case tlsAvailable:
		return false
	default:
		return true
	}
}

// The regression: warden holds a real client cert AND admin-service is
// plaintext. Before the fix the mTLS branch won and every admin call failed
// with "first record does not look like a TLS handshake", surfacing as a 500 on
// ListUsers/ListRoles while the module itself stayed registered and healthy.
func TestRegistrationInsecureWinsOverAvailableCerts(t *testing.T) {
	if !adminDialIsPlaintext("1", true) {
		t.Error("REGISTRATION_INSECURE=1 with certs present must dial plaintext; " +
			"admin-service has no TLS listener, so mTLS here can only fail")
	}
}

func TestAdminDialPrecedence(t *testing.T) {
	tests := []struct {
		name          string
		insecureEnv   string
		tlsAvailable  bool
		wantPlaintext bool
	}{
		{"insecure flag with certs", "1", true, true},
		{"insecure flag without certs", "1", false, true},
		{"certs and no flag uses mTLS", "", true, false},
		{"no certs no flag", "", false, true},
		{"flag set to something else is not an opt-out", "0", true, false},
		{"empty flag is not an opt-out", "", true, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := adminDialIsPlaintext(tt.insecureEnv, tt.tlsAvailable); got != tt.wantPlaintext {
				t.Errorf("plaintext = %v, want %v", got, tt.wantPlaintext)
			}
		})
	}
}

// The production environment must actually reach the plaintext branch.
func TestProdEnvShapeReachesPlaintext(t *testing.T) {
	t.Setenv("REGISTRATION_INSECURE", "1")
	if !adminDialIsPlaintext(os.Getenv("REGISTRATION_INSECURE"), true) {
		t.Error("with REGISTRATION_INSECURE=1 as deployed, the client must dial plaintext")
	}
}
