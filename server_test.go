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
)

func TestServer(t *testing.T) {
	cert := newServerCertificate(t)

	t.Run("no handler", func(t *testing.T) {
		addr := startServer(t, cert, nil)
		res := send(t, addr, "gemini://example.com/path\r\n")
		assertResponse(t, res, "51\r\n")
	})

	t.Run("request too long", func(t *testing.T) {
		addr := startServer(t, cert, nil)
		res := send(t, addr, fmt.Sprintf("/%s\r\n", strings.Repeat("x", 1024)))
		assertResponse(t, res, "59 Request is too long\r\n")
	})

	t.Run("request malformed", func(t *testing.T) {
		addr := startServer(t, cert, nil)
		res := send(t, addr, "gemini://example.com/\n")
		assertResponse(t, res, "59 Request is malformed\r\n")
	})

	t.Run("request too short", func(t *testing.T) {
		addr := startServer(t, cert, nil)
		res := send(t, addr, "\r\n")
		assertResponse(t, res, "59 Request is too short\r\n")
	})

	t.Run("malformed url", func(t *testing.T) {
		addr := startServer(t, cert, nil)
		res := send(t, addr, ":\r\n")
		assertResponse(t, res, "59 The URL is malformed\r\n")
	})

	t.Run("no scheme", func(t *testing.T) {
		addr := startServer(t, cert, nil)
		res := send(t, addr, "//example.com/path\r\n")
		assertResponse(t, res, "59 The URL has no scheme\r\n")
	})

	t.Run("unsupported scheme", func(t *testing.T) {
		addr := startServer(t, cert, nil)
		res := send(t, addr, "https://example.com/path\r\n")
		assertResponse(t, res, "53 Unsupported protocol\r\n")
	})

	t.Run("no host", func(t *testing.T) {
		addr := startServer(t, cert, nil)
		res := send(t, addr, "gemini:///path\r\n")
		assertResponse(t, res, "59 The URL has no host\r\n")
	})

	t.Run("path with control characters", func(t *testing.T) {
		addr := startServer(t, cert, nil)
		res := send(t, addr, "gemini://example.com/x%0Ax\r\n")
		assertResponse(t, res, "59 The URL path contains control characters\r\n")
	})

	t.Run("user info", func(t *testing.T) {
		addr := startServer(t, cert, nil)
		res := send(t, addr, "gemini://user@example.com/path\r\n")
		assertResponse(t, res, "59 The URL has user info\r\n")
	})

	t.Run("fragment", func(t *testing.T) {
		addr := startServer(t, cert, nil)
		res := send(t, addr, "gemini://example.com/path#fragment\r\n")
		assertResponse(t, res, "59 The URL has a fragment\r\n")
	})

	t.Run("handler", func(t *testing.T) {
		addr := startServer(t, cert, gemini.HandlerFunc(func(ctx context.Context, r *gemini.Request, w gemini.ResponseWriter) {
			if ctx == nil {
				t.Errorf("context is nil")
			}

			if r.Scheme != "gemini" {
				t.Errorf("invalid scheme: %v", r.Scheme)
			}

			if r.Host != "example.com" {
				t.Errorf("invalid host: %v", r.Host)
			}

			if r.Port != 1234 {
				t.Errorf("invalid port: %v", r.Port)
			}

			if r.Path != "/path" {
				t.Errorf("invalid path: %v", r.Path)
			}

			if r.Query != "query" {
				t.Errorf("invalid query: %v", r.Query)
			}

			if r.Cert != nil {
				t.Errorf("certificate is not nil")
			}

			w.Write([]byte("Some text\r\n"))
		}))

		res := send(t, addr, "gemini://example.com:1234/path?query\r\n")
		assertResponse(t, res, "20 text/gemini\r\nSome text\r\n")
	})

	t.Run("empty path is normalized", func(t *testing.T) {
		addr := startServer(t, cert, gemini.HandlerFunc(func(ctx context.Context, r *gemini.Request, w gemini.ResponseWriter) {
			if r.Path != "/" {
				t.Errorf("invalid path: %v", r.Path)
			}
		}))

		send(t, addr, "gemini://example.com\r\n")
	})

	t.Run("final slash is preserved", func(t *testing.T) {
		addr := startServer(t, cert, gemini.HandlerFunc(func(ctx context.Context, r *gemini.Request, w gemini.ResponseWriter) {
			if r.Path != "/foo/" {
				t.Errorf("invalid path: %v", r.Path)
			}
		}))

		send(t, addr, "gemini://example.com/foo/\r\n")
	})

	t.Run("client certificate", func(t *testing.T) {
		addr := startServer(t, cert, gemini.HandlerFunc(func(ctx context.Context, r *gemini.Request, w gemini.ResponseWriter) {
			if r.Cert == nil {
				t.Errorf("no client certificate")
			}

			if r.Cert.Subject.CommonName != "client" {
				t.Errorf("invalid certificate")
			}
		}))

		res := sendWithIdentity(t, newClientCertificate(t), addr, "gemini://example.com/\r\n")
		assertResponse(t, res, "20 text/gemini\r\n")
	})

	t.Run("client certificate not yet valid", func(t *testing.T) {
		addr := startServer(t, cert, nil)
		res := sendWithIdentity(t, newClientCertificateNotYetValid(t), addr, "gemini://example.com/\r\n")
		assertResponse(t, res, "62 Certificate not yet valid\r\n")
	})

	t.Run("client certificate expired", func(t *testing.T) {
		addr := startServer(t, cert, nil)
		res := sendWithIdentity(t, newClientCertificateExpired(t), addr, "gemini://example.com/\r\n")
		assertResponse(t, res, "62 Certificate expired\r\n")
	})

	t.Run("client certificate signature invalid", func(t *testing.T) {
		addr := startServer(t, cert, nil)
		res := sendWithIdentity(t, newClientCertificateInvalidSignature(t), addr, "gemini://example.com/\r\n")
		assertResponse(t, res, "62 Invalid signature\r\n")
	})

	t.Run("status code too low", func(t *testing.T) {
		addr := startServer(t, cert, gemini.HandlerFunc(func(ctx context.Context, r *gemini.Request, w gemini.ResponseWriter) {
			defer assertPanics(t, "invalid status code")
			w.WriteHeader(9, "")
		}))
		send(t, addr, "gemini://example.com/\r\n")
	})

	t.Run("status code too high", func(t *testing.T) {
		addr := startServer(t, cert, gemini.HandlerFunc(func(ctx context.Context, r *gemini.Request, w gemini.ResponseWriter) {
			defer assertPanics(t, "invalid status code")
			w.WriteHeader(70, "")
		}))
		send(t, addr, "gemini://example.com/\r\n")
	})

	t.Run("status code in range but undefined", func(t *testing.T) {
		addr := startServer(t, cert, gemini.HandlerFunc(func(ctx context.Context, r *gemini.Request, w gemini.ResponseWriter) {
			defer assertPanics(t, "invalid status code")
			w.WriteHeader(21, "")
		}))
		send(t, addr, "gemini://example.com/\r\n")
	})

	t.Run("meta with control characters", func(t *testing.T) {
		addr := startServer(t, cert, gemini.HandlerFunc(func(ctx context.Context, r *gemini.Request, w gemini.ResponseWriter) {
			defer assertPanics(t, "meta contains control characters")
			w.WriteHeader(gemini.StatusTemporaryFailure, "x\nx")
		}))
		send(t, addr, "gemini://example.com/\r\n")
	})

	t.Run("input expected requires meta", func(t *testing.T) {
		addr := startServer(t, cert, gemini.HandlerFunc(func(ctx context.Context, r *gemini.Request, w gemini.ResponseWriter) {
			defer assertPanics(t, "sending an input without a prompt")
			w.WriteHeader(gemini.StatusInputExpected, "")
		}))
		send(t, addr, "gemini://example.com/\r\n")
	})

	t.Run("sensitive input expected requires meta", func(t *testing.T) {
		addr := startServer(t, cert, gemini.HandlerFunc(func(ctx context.Context, r *gemini.Request, w gemini.ResponseWriter) {
			defer assertPanics(t, "sending a sensitive input without a prompt")
			w.WriteHeader(gemini.StatusSensitiveInput, "")
		}))
		send(t, addr, "gemini://example.com/\r\n")
	})

	t.Run("success requires meta", func(t *testing.T) {
		addr := startServer(t, cert, gemini.HandlerFunc(func(ctx context.Context, r *gemini.Request, w gemini.ResponseWriter) {
			defer assertPanics(t, "sending a success without a media type")
			w.WriteHeader(gemini.StatusSuccess, "")
		}))
		send(t, addr, "gemini://example.com/\r\n")
	})

	t.Run("success requires valid media type", func(t *testing.T) {
		addr := startServer(t, cert, gemini.HandlerFunc(func(ctx context.Context, r *gemini.Request, w gemini.ResponseWriter) {
			defer assertPanics(t, "invalid media type")
			w.WriteHeader(gemini.StatusSuccess, "not some media type")
		}))
		send(t, addr, "gemini://example.com/\r\n")
	})

	t.Run("temporary redirect requires meta", func(t *testing.T) {
		addr := startServer(t, cert, gemini.HandlerFunc(func(ctx context.Context, r *gemini.Request, w gemini.ResponseWriter) {
			defer assertPanics(t, "sending a temporary redirection without a URI")
			w.WriteHeader(gemini.StatusTemporaryRedirection, "")
		}))
		send(t, addr, "gemini://example.com/\r\n")
	})

	t.Run("temporary redirect requires valid url", func(t *testing.T) {
		addr := startServer(t, cert, gemini.HandlerFunc(func(ctx context.Context, r *gemini.Request, w gemini.ResponseWriter) {
			defer assertPanics(t, "invalid URL")
			w.WriteHeader(gemini.StatusTemporaryRedirection, ":")
		}))
		send(t, addr, "gemini://example.com/\r\n")
	})

	t.Run("permanent redirect requires meta", func(t *testing.T) {
		addr := startServer(t, cert, gemini.HandlerFunc(func(ctx context.Context, r *gemini.Request, w gemini.ResponseWriter) {
			defer assertPanics(t, "sending a permanent redirection without a URI")
			w.WriteHeader(gemini.StatusPermanentRedirection, "")
		}))
		send(t, addr, "gemini://example.com/\r\n")
	})

	t.Run("permanent redirect requires valid url", func(t *testing.T) {
		addr := startServer(t, cert, gemini.HandlerFunc(func(ctx context.Context, r *gemini.Request, w gemini.ResponseWriter) {
			defer assertPanics(t, "invalid URL")
			w.WriteHeader(gemini.StatusPermanentRedirection, ":")
		}))
		send(t, addr, "gemini://example.com/\r\n")
	})

	t.Run("panic handling", func(t *testing.T) {
		addr := startServer(t, cert, gemini.HandlerFunc(func(ctx context.Context, r *gemini.Request, w gemini.ResponseWriter) {
			panic("something went wrong")
		}))
		res := send(t, addr, "gemini://example.com/\r\n")
		assertResponse(t, res, "42 Panic\r\n")
	})
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

func send(t *testing.T, addr string, url string) string {
	t.Helper()

	config := tls.Config{
		InsecureSkipVerify: true,
	}

	conn, err := tls.Dial("tcp", addr, &config)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}

	defer func() {
		if err := conn.Close(); err != nil {
			t.Errorf("close: %v", err)
		}
	}()

	if _, err := conn.Write([]byte(url)); err != nil {
		t.Fatalf("write: %v", err)
	}

	data, err := io.ReadAll(conn)
	if err != nil {
		t.Fatalf("read all: %v", err)
	}

	return string(data)
}

func sendWithIdentity(t *testing.T, cert tls.Certificate, addr string, url string) string {
	t.Helper()

	config := tls.Config{
		InsecureSkipVerify: true,
		Certificates:       []tls.Certificate{cert},
	}

	conn, err := tls.Dial("tcp", addr, &config)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}

	defer func() {
		if err := conn.Close(); err != nil {
			t.Errorf("close: %v", err)
		}
	}()

	if _, err := conn.Write([]byte(url)); err != nil {
		t.Fatalf("write: %v", err)
	}

	data, err := io.ReadAll(conn)
	if err != nil {
		t.Fatalf("read all: %v", err)
	}

	return string(data)
}

func assertResponse(t *testing.T, got string, expected string) {
	t.Helper()

	if got != expected {
		t.Fatalf("invalid response: expected %q, got %q", expected, got)
	}
}

func assertPanics(t *testing.T, expected string) {
	v := recover()

	if v == nil {
		t.Errorf("no value recovered")
		return
	}

	s, ok := v.(string)
	if !ok {
		t.Errorf("recovered value is not a string")
		return
	}

	if s != expected {
		t.Errorf("invalid recovered value, expecting %q, got %q", expected, s)
	}
}
