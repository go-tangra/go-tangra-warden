package secrets

import (
	"strings"
	"testing"
	"time"
)

func TestNormalizeSeed(t *testing.T) {
	const b32 = "JBSWY3DPEHPK3PXP"
	got, err := NormalizeSeed(" jbsw y3dp ehpk 3pxp ")
	if err != nil || got != "otpauth://totp/warden?secret="+b32 {
		t.Fatalf("%q %v", got, err)
	}
	got, err = NormalizeSeed("otpauth://totp/Example:alice@example.org?secret=" + b32 + "&issuer=Example&algorithm=sha256&digits=8&period=60")
	if err != nil || !strings.HasPrefix(got, "otpauth://totp/Example:alice@example.org?") || !strings.Contains(got, "algorithm=SHA256") || !strings.Contains(got, "digits=8") || !strings.Contains(got, "period=60") || !strings.Contains(got, "issuer=Example") {
		t.Fatalf("%q %v", got, err)
	}
	got, _ = NormalizeSeed("otpauth://totp/?secret=" + b32 + "&algorithm=SHA1&digits=6&period=30")
	if got != "otpauth://totp/warden?secret="+b32 {
		t.Fatalf("defaults not stripped: %q", got)
	}
	for _, bad := range []string{"", "short", strings.Repeat("A", 600), "otpauth://hotp/x?secret=" + b32, "otpauth://totp/x?secret=1", "otpauth://totp/x?secret=" + b32 + "&algorithm=MD5",
		"otpauth://totp/x?secret=" + b32 + "&digits=7", "otpauth://totp/x?secret=" + b32 + "&period=5", "otpauth://totp/x?secret=" + b32 + "&period=abc", "otpauth://totp/%zz?secret=" + b32, "not base32 !!"} {
		if _, err := NormalizeSeed(bad); err == nil {
			t.Errorf("%q accepted", bad)
		}
	}
}

func TestGenerateCode(t *testing.T) {
	now := time.Unix(1_700_000_000, 0)
	c, err := GenerateCode("otpauth://totp/warden?secret=JBSWY3DPEHPK3PXP", now)
	if err != nil || len(c.Code) != 6 || c.Period != 30 || c.ExpiresIn != 30-int(now.Unix()%30) {
		t.Fatalf("%+v %v", c, err)
	}
	c8, _ := GenerateCode("otpauth://totp/warden?secret=JBSWY3DPEHPK3PXP&digits=8&period=60&algorithm=SHA512", now)
	if len(c8.Code) != 8 || c8.Period != 60 {
		t.Fatalf("%+v", c8)
	}
	if _, err := GenerateCode("garbage", now); err == nil {
		t.Fatal("garbage accepted")
	}
	if _, err := GenerateCode("otpauth://totp/warden?secret=%%%", now); err == nil {
		t.Fatal("bad url accepted")
	}
	if _, err := GenerateCode("otpauth://totp/warden?secret=1", now); err == nil {
		t.Fatal("bad secret accepted")
	}
}
