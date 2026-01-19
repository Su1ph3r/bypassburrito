package http

import (
	"crypto/tls"
	"math/rand"
	"sync"
)

// TLSFingerprint represents a TLS fingerprint profile
type TLSFingerprint struct {
	Name         string
	MinVersion   uint16
	MaxVersion   uint16
	CipherSuites []uint16
	CurvePrefs   []tls.CurveID
	ALPN         []string
}

// Common TLS fingerprint profiles
var (
	ChromeFingerprint = TLSFingerprint{
		Name:       "chrome",
		MinVersion: tls.VersionTLS12,
		MaxVersion: tls.VersionTLS13,
		CipherSuites: []uint16{
			tls.TLS_AES_128_GCM_SHA256,
			tls.TLS_AES_256_GCM_SHA384,
			tls.TLS_CHACHA20_POLY1305_SHA256,
			tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
			tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
			tls.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
			tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
			tls.TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256,
			tls.TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256,
		},
		CurvePrefs: []tls.CurveID{
			tls.X25519,
			tls.CurveP256,
			tls.CurveP384,
		},
		ALPN: []string{"h2", "http/1.1"},
	}

	FirefoxFingerprint = TLSFingerprint{
		Name:       "firefox",
		MinVersion: tls.VersionTLS12,
		MaxVersion: tls.VersionTLS13,
		CipherSuites: []uint16{
			tls.TLS_AES_128_GCM_SHA256,
			tls.TLS_CHACHA20_POLY1305_SHA256,
			tls.TLS_AES_256_GCM_SHA384,
			tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
			tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
			tls.TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256,
			tls.TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256,
			tls.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
			tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
		},
		CurvePrefs: []tls.CurveID{
			tls.X25519,
			tls.CurveP256,
			tls.CurveP384,
			tls.CurveP521,
		},
		ALPN: []string{"h2", "http/1.1"},
	}

	SafariFingerprint = TLSFingerprint{
		Name:       "safari",
		MinVersion: tls.VersionTLS12,
		MaxVersion: tls.VersionTLS13,
		CipherSuites: []uint16{
			tls.TLS_AES_128_GCM_SHA256,
			tls.TLS_AES_256_GCM_SHA384,
			tls.TLS_CHACHA20_POLY1305_SHA256,
			tls.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
			tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
			tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
			tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
			tls.TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256,
			tls.TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256,
		},
		CurvePrefs: []tls.CurveID{
			tls.X25519,
			tls.CurveP256,
			tls.CurveP384,
			tls.CurveP521,
		},
		ALPN: []string{"h2", "http/1.1"},
	}

	// Map of available fingerprints
	AvailableFingerprints = map[string]TLSFingerprint{
		"chrome":  ChromeFingerprint,
		"firefox": FirefoxFingerprint,
		"safari":  SafariFingerprint,
	}
)

// FingerprintRotator rotates TLS fingerprints
type FingerprintRotator struct {
	mu           sync.Mutex
	profiles     []TLSFingerprint
	currentIndex int
	rotate       bool
}

// NewFingerprintRotator creates a new fingerprint rotator
func NewFingerprintRotator(profiles []string, rotate bool) *FingerprintRotator {
	var fps []TLSFingerprint

	for _, name := range profiles {
		if fp, ok := AvailableFingerprints[name]; ok {
			fps = append(fps, fp)
		}
	}

	// Default to all if none specified
	if len(fps) == 0 {
		fps = []TLSFingerprint{ChromeFingerprint, FirefoxFingerprint, SafariFingerprint}
	}

	return &FingerprintRotator{
		profiles:     fps,
		currentIndex: 0,
		rotate:       rotate,
	}
}

// Next returns the next fingerprint
func (r *FingerprintRotator) Next() TLSFingerprint {
	r.mu.Lock()
	defer r.mu.Unlock()

	if !r.rotate {
		return r.profiles[0]
	}

	fp := r.profiles[r.currentIndex]
	r.currentIndex = (r.currentIndex + 1) % len(r.profiles)
	return fp
}

// Random returns a random fingerprint
func (r *FingerprintRotator) Random() TLSFingerprint {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.profiles[rand.Intn(len(r.profiles))]
}

// Current returns the current fingerprint without advancing
func (r *FingerprintRotator) Current() TLSFingerprint {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.profiles[r.currentIndex]
}

// ApplyToConfig applies a fingerprint to a TLS config
func (fp *TLSFingerprint) ApplyToConfig(config *tls.Config) {
	config.MinVersion = fp.MinVersion
	config.MaxVersion = fp.MaxVersion
	config.CipherSuites = fp.CipherSuites
	config.CurvePreferences = fp.CurvePrefs
	config.NextProtos = fp.ALPN
}

// GetTLSConfig returns a TLS config with this fingerprint
func (fp *TLSFingerprint) GetTLSConfig(insecureSkipVerify bool) *tls.Config {
	config := &tls.Config{
		InsecureSkipVerify: insecureSkipVerify,
		MinVersion:         fp.MinVersion,
		MaxVersion:         fp.MaxVersion,
		CipherSuites:       fp.CipherSuites,
		CurvePreferences:   fp.CurvePrefs,
		NextProtos:         fp.ALPN,
	}
	return config
}
