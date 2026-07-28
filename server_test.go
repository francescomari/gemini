package gemini_test

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"math/big"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/francescomari/gemini"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestServer(t *testing.T) {
	cert := newServerCertificate(t)

	t.Run("no handler", func(t *testing.T) {
		addr := startServer(t, cert, nil)
		res := sendAnonymous(t, addr, "gemini://example.com/path\r\n")
		require.Equal(t, "51\r\n", res)
	})

	t.Run("server validation", func(t *testing.T) {
		tests := []struct {
			name     string
			request  string
			response string
		}{
			{"request too long", fmt.Sprintf("/%s\r\n", strings.Repeat("x", 1024)), "59 Request is too long\r\n"},
			{"request malformed", "gemini://example.com/\n", "59 Request is malformed\r\n"},
			{"request too short", "\r\n", "59 Request is too short\r\n"},
			{"malformed url", ":\r\n", "59 The URL is malformed\r\n"},
			{"no scheme", "//example.com/path\r\n", "59 The URL has no scheme\r\n"},
			{"unsupported scheme", "https://example.com/path\r\n", "53 Unsupported protocol\r\n"},
			{"no host", "gemini:///path\r\n", "59 The URL has no host\r\n"},
			{"path with control characters", "gemini://example.com/x%0Ax\r\n", "59 The URL path contains control characters\r\n"},
			{"user info", "gemini://user@example.com/path\r\n", "59 The URL has user info\r\n"},
			{"fragment", "gemini://example.com/path#fragment\r\n", "59 The URL has a fragment\r\n"},
		}

		for _, test := range tests {
			t.Run(test.name, func(t *testing.T) {
				addr := startServer(t, cert, handlerShouldNotBeCalled(t))
				res := sendAnonymous(t, addr, test.request)
				require.Equal(t, test.response, res)
			})
		}
	})

	t.Run("handler", func(t *testing.T) {
		handler := gemini.HandlerFunc(func(ctx context.Context, r *gemini.Request, w gemini.ResponseWriter) {
			assert.NotNil(t, ctx)
			assert.Equal(t, "gemini", r.Scheme)
			assert.Equal(t, "example.com", r.Host)
			assert.Equal(t, 1234, r.Port)
			assert.Equal(t, "/path", r.Path)
			assert.Equal(t, "query", r.Query)
			assert.Nil(t, r.Cert)
			w.Write([]byte("Some text\r\n"))
		})
		addr := startServer(t, cert, handler)
		res := sendAnonymous(t, addr, "gemini://example.com:1234/path?query\r\n")
		require.Equal(t, "20 text/gemini\r\nSome text\r\n", res)
	})

	t.Run("empty path is normalized", func(t *testing.T) {
		handler := gemini.HandlerFunc(func(ctx context.Context, r *gemini.Request, w gemini.ResponseWriter) {
			assert.Equal(t, "/", r.Path)
		})
		addr := startServer(t, cert, handler)
		sendAnonymous(t, addr, "gemini://example.com\r\n")
	})

	t.Run("final slash is preserved", func(t *testing.T) {
		handler := gemini.HandlerFunc(func(ctx context.Context, r *gemini.Request, w gemini.ResponseWriter) {
			assert.Equal(t, "/foo/", r.Path)
		})
		addr := startServer(t, cert, handler)
		sendAnonymous(t, addr, "gemini://example.com/foo/\r\n")
	})

	t.Run("client certificate", func(t *testing.T) {
		handler := gemini.HandlerFunc(func(ctx context.Context, r *gemini.Request, w gemini.ResponseWriter) {
			assert.NotNil(t, r.Cert)
			assert.Equal(t, "client", r.Cert.Subject.CommonName)
		})
		addr := startServer(t, cert, handler)
		res := sendWithIdentity(t, newClientCertificate(t), addr, "gemini://example.com/\r\n")
		require.Equal(t, "20 text/gemini\r\n", res)
	})

	t.Run("client certificate validation", func(t *testing.T) {
		tests := []struct {
			name     string
			cert     tls.Certificate
			response string
		}{
			{"not yet valid", newClientCertificateNotYetValid(t), "62 Certificate not yet valid\r\n"},
			{"expired", newClientCertificateExpired(t), "62 Certificate expired\r\n"},
			{"invalid signature", newClientCertificateInvalidSignature(t), "62 Invalid signature\r\n"},
		}

		for _, test := range tests {
			t.Run(test.name, func(t *testing.T) {
				addr := startServer(t, cert, handlerShouldNotBeCalled(t))
				res := sendWithIdentity(t, test.cert, addr, "gemini://example.com/\r\n")
				require.Equal(t, test.response, res)
			})
		}
	})

	t.Run("writer panic", func(t *testing.T) {
		tests := []struct {
			name       string
			statusCode gemini.StatusCode
			meta       string
			value      string
		}{
			{"status code too low", 9, "", "invalid status code"},
			{"status code too high", 70, "", "invalid status code"},
			{"unspecified status code", 21, "", "invalid status code"},
			{"control characters", gemini.StatusTemporaryFailure, "\n", "meta contains control characters"},
			{"input without meta", gemini.StatusInputExpected, "", "sending an input without a prompt"},
			{"sensitive input without meta", gemini.StatusSensitiveInput, "", "sending a sensitive input without a prompt"},
			{"success without media type", gemini.StatusSuccess, "", "sending a success without a media type"},
			{"invalid media type", gemini.StatusSuccess, "not a media type", "invalid media type"},
			{"temporary redirection without uri", gemini.StatusTemporaryRedirection, "", "sending a temporary redirection without a URI"},
			{"permanent redirection without uri", gemini.StatusPermanentRedirection, "", "sending a permanent redirection without a URI"},
			{"temporary redirection with invalid uri", gemini.StatusTemporaryRedirection, ":", "invalid URI"},
			{"permanent redirection with invalid uri", gemini.StatusPermanentRedirection, ":", "invalid URI"},
		}

		for _, test := range tests {
			t.Run(test.name, func(t *testing.T) {
				handler := gemini.HandlerFunc(func(ctx context.Context, r *gemini.Request, w gemini.ResponseWriter) {
					assert.PanicsWithValue(t, test.value, func() {
						w.WriteHeader(test.statusCode, test.meta)
					})
				})
				addr := startServer(t, cert, handler)
				sendAnonymous(t, addr, "gemini://example.com/\r\n")
			})
		}
	})

	t.Run("panic", func(t *testing.T) {
		handler := gemini.HandlerFunc(func(ctx context.Context, r *gemini.Request, w gemini.ResponseWriter) {
			panic("something went wrong")
		})
		addr := startServer(t, cert, handler)
		res := sendAnonymous(t, addr, "gemini://example.com/\r\n")
		require.Equal(t, "42 Panic\r\n", res)
	})
}

func handlerShouldNotBeCalled(t *testing.T) gemini.HandlerFunc {
	return func(ctx context.Context, r *gemini.Request, w gemini.ResponseWriter) {
		assert.Fail(t, "the handler should not be called")
	}
}

func newServerCertificate(t *testing.T) tls.Certificate {
	t.Helper()

	return newCertificate(t, &x509.Certificate{
		Subject:      pkix.Name{CommonName: "localhost"},
		DNSNames:     []string{"localhost"},
		NotBefore:    time.Now(),
		NotAfter:     time.Now().AddDate(10, 0, 0),
		SerialNumber: newSerialNumber(t),
	})
}

func newClientCertificate(t *testing.T) tls.Certificate {
	t.Helper()

	return newCertificate(t, &x509.Certificate{
		Subject:      pkix.Name{CommonName: "client"},
		NotBefore:    time.Now().AddDate(-5, 0, 0),
		NotAfter:     time.Now().AddDate(5, 0, 0),
		SerialNumber: newSerialNumber(t),
	})
}

func newClientCertificateNotYetValid(t *testing.T) tls.Certificate {
	t.Helper()

	return newCertificate(t, &x509.Certificate{
		Subject:      pkix.Name{CommonName: "client"},
		NotBefore:    time.Now().AddDate(0, 0, 1),
		NotAfter:     time.Now().AddDate(10, 0, 1),
		SerialNumber: newSerialNumber(t),
	})
}

func newClientCertificateExpired(t *testing.T) tls.Certificate {
	t.Helper()

	return newCertificate(t, &x509.Certificate{
		Subject:      pkix.Name{CommonName: "client"},
		NotBefore:    time.Now().AddDate(-10, 0, 0),
		NotAfter:     time.Now().AddDate(-10, 0, -1),
		SerialNumber: newSerialNumber(t),
	})
}

func newClientCertificateInvalidSignature(t *testing.T) tls.Certificate {
	t.Helper()

	cert := newCertificate(t, &x509.Certificate{
		Subject:      pkix.Name{CommonName: "client"},
		NotBefore:    time.Now().AddDate(-5, 0, 0),
		NotAfter:     time.Now().AddDate(5, 0, 0),
		SerialNumber: newSerialNumber(t),
	})

	cert.Leaf.Signature[0] += 1

	return cert
}

func newCertificate(t *testing.T, template *x509.Certificate) tls.Certificate {
	t.Helper()

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}

	keyDER, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		t.Fatalf("marshal key: %v", err)
	}

	certDER, err := x509.CreateCertificate(rand.Reader, template, template, key.Public(), key)
	if err != nil {
		t.Fatalf("create certificate: %v", err)
	}

	keyPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "EC PRIVATE KEY",
		Bytes: keyDER,
	})

	certPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "CERTIFICATE",
		Bytes: certDER,
	})

	cert, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		t.Fatalf("create X.509 key pair: %v", err)
	}

	return cert
}

func newSerialNumber(t *testing.T) *big.Int {
	t.Helper()

	serial, err := rand.Int(rand.Reader, big.NewInt(0).Lsh(big.NewInt(1), 128))
	if err != nil {
		t.Fatalf("generate serial number")
	}

	return serial
}

func startServer(t *testing.T, cert tls.Certificate, handler gemini.Handler) string {
	t.Helper()

	listener, err := net.Listen("tcp", net.JoinHostPort("localhost", "0"))
	if err != nil {
		t.Fatalf("listen: %v", err)
	}

	done := make(chan struct{})

	t.Cleanup(func() {
		<-done
	})

	go func() {
		defer close(done)

		server := gemini.Server{
			Cert:    cert,
			Handler: handler,
		}

		if err := server.Serve(t.Context(), listener); !errors.Is(err, context.Canceled) {
			t.Errorf("serve: %v", err)
		}
	}()

	return listener.Addr().String()
}

func sendAnonymous(t *testing.T, addr string, request string) string {
	t.Helper()

	config := tls.Config{
		InsecureSkipVerify: true,
	}

	return send(t, &config, addr, request)
}

func sendWithIdentity(t *testing.T, cert tls.Certificate, addr string, request string) string {
	t.Helper()

	config := tls.Config{
		InsecureSkipVerify: true,
		Certificates:       []tls.Certificate{cert},
	}

	return send(t, &config, addr, request)
}

func send(t *testing.T, config *tls.Config, addr string, request string) string {
	t.Helper()

	conn, err := tls.Dial("tcp", addr, config)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}

	defer func() {
		if err := conn.Close(); err != nil {
			t.Errorf("close: %v", err)
		}
	}()

	if _, err := conn.Write([]byte(request)); err != nil {
		t.Fatalf("write: %v", err)
	}

	data, err := io.ReadAll(conn)
	if err != nil {
		t.Fatalf("read all: %v", err)
	}

	return string(data)
}
