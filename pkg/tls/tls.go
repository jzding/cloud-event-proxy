package tls

import (
	"crypto/tls"
	"net/http"
	"os"
	"strings"
	"time"

	log "github.com/sirupsen/logrus"
)

const (
	EnvTLSCertFile     = "TLS_CERT_FILE"
	EnvTLSKeyFile      = "TLS_KEY_FILE"
	EnvTLSMinVersion   = "TLS_MIN_VERSION"
	EnvTLSCipherSuites = "TLS_CIPHER_SUITES"
)

// ianaToGoCipher maps IANA cipher suite names (as passed by the operator) to
// Go crypto/tls cipher suite IDs.
var ianaToGoCipher = map[string]uint16{
	"TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256":       tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
	"TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256":         tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
	"TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384":       tls.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
	"TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384":         tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
	"TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256": tls.TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256,
	"TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256":   tls.TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256,
	"TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256":       tls.TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256,
	"TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256":         tls.TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256,
	"TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA":          tls.TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA,
	"TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA":            tls.TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA,
	"TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA":          tls.TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA,
	"TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA":            tls.TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA,
	"TLS_RSA_WITH_AES_128_GCM_SHA256":               tls.TLS_RSA_WITH_AES_128_GCM_SHA256,
	"TLS_RSA_WITH_AES_256_GCM_SHA384":               tls.TLS_RSA_WITH_AES_256_GCM_SHA384,
	"TLS_RSA_WITH_AES_128_CBC_SHA256":                tls.TLS_RSA_WITH_AES_128_CBC_SHA256,
	"TLS_RSA_WITH_AES_128_CBC_SHA":                   tls.TLS_RSA_WITH_AES_128_CBC_SHA,
	"TLS_RSA_WITH_AES_256_CBC_SHA":                   tls.TLS_RSA_WITH_AES_256_CBC_SHA,
	"TLS_RSA_WITH_3DES_EDE_CBC_SHA":                  tls.TLS_RSA_WITH_3DES_EDE_CBC_SHA,
}

var tlsVersionMap = map[string]uint16{
	"VersionTLS10": tls.VersionTLS10,
	"VersionTLS11": tls.VersionTLS11,
	"VersionTLS12": tls.VersionTLS12,
	"VersionTLS13": tls.VersionTLS13,
}

// Enabled returns true when TLS certificate files are configured via
// environment variables.
func Enabled() bool {
	cert := os.Getenv(EnvTLSCertFile)
	key := os.Getenv(EnvTLSKeyFile)
	return cert != "" && key != ""
}

// CertKeyPaths returns the certificate and key file paths from environment
// variables.
func CertKeyPaths() (certFile, keyFile string) {
	return os.Getenv(EnvTLSCertFile), os.Getenv(EnvTLSKeyFile)
}

// NewTLSConfig builds a tls.Config from environment variables set by the
// ptp-operator based on the cluster's TLS security profile. Returns nil if
// TLS is not configured.
func NewTLSConfig() *tls.Config {
	if !Enabled() {
		return nil
	}

	cfg := &tls.Config{
		MinVersion: tls.VersionTLS12,
	}

	if minVer := os.Getenv(EnvTLSMinVersion); minVer != "" {
		if v, ok := tlsVersionMap[minVer]; ok {
			cfg.MinVersion = v
		} else {
			log.Warnf("unrecognised TLS min version %q, using TLS 1.2", minVer)
		}
	}

	if cipherStr := os.Getenv(EnvTLSCipherSuites); cipherStr != "" {
		names := strings.Split(cipherStr, ",")
		var suites []uint16
		for _, name := range names {
			name = strings.TrimSpace(name)
			if id, ok := ianaToGoCipher[name]; ok {
				suites = append(suites, id)
			} else {
				log.Warnf("skipping unsupported cipher suite %q", name)
			}
		}
		if len(suites) > 0 {
			cfg.CipherSuites = suites
		}
	}

	log.Infof("TLS configured: minVersion=%s cipherSuites=%d",
		os.Getenv(EnvTLSMinVersion), len(cfg.CipherSuites))
	return cfg
}

// NewServer creates an http.Server with TLS configuration from the cluster
// TLS security profile when TLS is enabled, or a plain HTTP server otherwise.
func NewServer(addr string, handler http.Handler) *http.Server {
	srv := &http.Server{
		Addr:              addr,
		ReadHeaderTimeout: 5 * time.Second,
		Handler:           handler,
	}

	if tlsCfg := NewTLSConfig(); tlsCfg != nil {
		srv.TLSConfig = tlsCfg
	}

	return srv
}

// ListenAndServe starts the server with TLS if configured, plain HTTP
// otherwise.
func ListenAndServe(srv *http.Server) error {
	if srv.TLSConfig != nil {
		certFile, keyFile := CertKeyPaths()
		log.Infof("starting TLS server on %s", srv.Addr)
		return srv.ListenAndServeTLS(certFile, keyFile)
	}
	log.Infof("starting HTTP server on %s (TLS not configured)", srv.Addr)
	return srv.ListenAndServe()
}
