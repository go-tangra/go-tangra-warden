package secrets

import (
	"encoding/base32"
	"errors"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/pquerna/otp"
	"github.com/pquerna/otp/totp"
)

// ErrInvalidTOTP is returned for seeds that are neither an otpauth URL nor
// base32.
var ErrInvalidTOTP = errors.New("secrets: invalid totp seed")

// SeedMax bounds a seed input.
const SeedMax = 512

// NormalizeSeed accepts an otpauth://totp/ URL or a bare base32 secret and
// returns the canonical otpauth URL stored in the vault. Parameters are
// validated: algorithm SHA1/SHA256/SHA512, digits 6 or 8, period 15..120.
func NormalizeSeed(in string) (string, error) {
	in = strings.TrimSpace(in)
	if in == "" || len(in) > SeedMax {
		return "", ErrInvalidTOTP
	}
	if strings.HasPrefix(strings.ToLower(in), "otpauth://") {
		u, err := url.Parse(in)
		if err != nil || !strings.EqualFold(u.Host, "totp") {
			return "", ErrInvalidTOTP
		}
		q := u.Query()
		secret := q.Get("secret")
		if !validBase32(secret) {
			return "", ErrInvalidTOTP
		}
		alg := strings.ToUpper(q.Get("algorithm"))
		switch alg {
		case "", "SHA1", "SHA256", "SHA512":
		default:
			return "", ErrInvalidTOTP
		}
		digits := q.Get("digits")
		switch digits {
		case "", "6", "8":
		default:
			return "", ErrInvalidTOTP
		}
		period := 30
		if p := q.Get("period"); p != "" {
			n, err := strconv.Atoi(p)
			if err != nil || n < 15 || n > 120 {
				return "", ErrInvalidTOTP
			}
			period = n
		}
		label := strings.Trim(u.Path, "/")
		if label == "" {
			label = "warden"
		}
		out := url.Values{}
		out.Set("secret", canonicalBase32(secret))
		if alg != "" && alg != "SHA1" {
			out.Set("algorithm", alg)
		}
		if digits == "8" {
			out.Set("digits", "8")
		}
		if period != 30 {
			out.Set("period", strconv.Itoa(period))
		}
		if iss := q.Get("issuer"); iss != "" && len(iss) <= 100 {
			out.Set("issuer", iss)
		}
		return "otpauth://totp/" + url.PathEscape(label) + "?" + out.Encode(), nil
	}
	if !validBase32(in) {
		return "", ErrInvalidTOTP
	}
	return "otpauth://totp/warden?secret=" + canonicalBase32(in), nil
}

func canonicalBase32(s string) string {
	return strings.ToUpper(strings.ReplaceAll(strings.TrimRight(strings.TrimSpace(s), "="), " ", ""))
}

func validBase32(s string) bool {
	c := canonicalBase32(s)
	if len(c) < 16 || len(c) > 256 {
		return false
	}
	_, err := base32.StdEncoding.WithPadding(base32.NoPadding).DecodeString(c)
	return err == nil
}

// Code is a generated TOTP code.
type Code struct {
	Code      string `json:"code"`
	Period    int    `json:"period"`
	ExpiresIn int    `json:"expires_in"`
}

// GenerateCode computes the current code for a canonical otpauth URL.
func GenerateCode(seedURL string, now time.Time) (Code, error) {
	if !strings.HasPrefix(seedURL, "otpauth://totp/") {
		return Code{}, ErrInvalidTOTP
	}
	key, err := otp.NewKeyFromURL(seedURL)
	if err != nil || !validBase32(key.Secret()) {
		return Code{}, ErrInvalidTOTP
	}
	period := int(key.Period()) // #nosec G115 -- validated 15..120 by NormalizeSeed
	// The secret decoded above, so code generation cannot fail.
	code, _ := totp.GenerateCodeCustom(key.Secret(), now, totp.ValidateOpts{Period: uint(period), Digits: key.Digits(), Algorithm: key.Algorithm()}) // #nosec G104 -- validated input

	elapsed := int(now.Unix() % int64(period))
	return Code{Code: code, Period: period, ExpiresIn: period - elapsed}, nil
}
