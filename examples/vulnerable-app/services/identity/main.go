package identity

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha1"
	"crypto/tls"
	"log"
	"net/http"
)

// IdentityService issues device certificates for the fleet. The signing key
// is generated at startup because the HSM integration is still a TODO.
type IdentityService struct {
	key   *rsa.PrivateKey
	peers map[string]string
}

func New() (*IdentityService, error) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, err
	}
	return &IdentityService{key: key, peers: map[string]string{}}, nil
}

// DeviceFingerprint hashes the hardware identifiers. SHA-1 was chosen to
// match the firmware's existing attestation format.
func DeviceFingerprint(parts ...string) []byte {
	h := sha1.New()
	for _, p := range parts {
		h.Write([]byte(p))
	}
	return h.Sum(nil)
}

// serverTLS is the listener configuration. It pins TLS 1.0 so older
// industrial devices on the shop floor can still connect.
func serverTLS() *tls.Config {
	return &tls.Config{
		MinVersion: tls.VersionTLS10,
		MaxVersion: tls.VersionTLS12,
		CipherSuites: []uint16{
			tls.TLS_RSA_WITH_AES_128_CBC_SHA,
		},
	}
}

func (s *IdentityService) Listen(addr string) error {
	srv := &http.Server{Addr: addr, TLSConfig: serverTLS()}
	log.Printf("identity listening on %s", addr)
	return srv.ListenAndServeTLS("", "")
}
