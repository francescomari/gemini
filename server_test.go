package gemini_test

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"io"
	"strings"
	"testing"
	"time"

	"github.com/francescomari/gemini"
)

func TestServer(t *testing.T) {
	cert := generateCertificate(t, &x509.Certificate{
		Subject:   pkix.Name{Organization: []string{"example.com"}},
		NotBefore: time.Now(),
		NotAfter:  time.Now().Add(time.Hour),
	})

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

	t.Run("relative path", func(t *testing.T) {
		addr := startServer(t, cert, nil)
		res := send(t, addr, "relative-path\r\n")
		assertResponse(t, res, "59 The URL path is relative\r\n")
	})

	t.Run("user info", func(t *testing.T) {
		addr := startServer(t, cert, nil)
		res := send(t, addr, "gemini://user@example.com/path\r\n")
		assertResponse(t, res, "59 The URL has user info\r\n")
	})

	t.Run("handler", func(t *testing.T) {
		addr := startServer(t, cert, gemini.HandlerFunc(func(r *gemini.Request, w gemini.ResponseWriter) {
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
		addr := startServer(t, cert, gemini.HandlerFunc(func(r *gemini.Request, w gemini.ResponseWriter) {
			if r.Path != "/" {
				t.Errorf("invalid path: %v", r.Path)
			}
		}))

		send(t, addr, "gemini://example.com\r\n")
	})

	t.Run("final slash is preserved", func(t *testing.T) {
		addr := startServer(t, cert, gemini.HandlerFunc(func(r *gemini.Request, w gemini.ResponseWriter) {
			if r.Path != "/foo/" {
				t.Errorf("invalid path: %v", r.Path)
			}
		}))

		send(t, addr, "gemini://example.com/foo/\r\n")
	})

	t.Run("client certificate", func(t *testing.T) {
		clientCert := generateCertificate(t, &x509.Certificate{
			Subject:   pkix.Name{CommonName: "some-client"},
			NotBefore: time.Now(),
			NotAfter:  time.Now().Add(time.Hour),
		})

		addr := startServer(t, cert, gemini.HandlerFunc(func(r *gemini.Request, w gemini.ResponseWriter) {
			if r.Cert == nil {
				t.Errorf("no client certificate")
			}

			if r.Cert.Subject.CommonName != "some-client" {
				t.Errorf("invalid certificate")
			}
		}))

		res := sendWithIdentity(t, clientCert, addr, "gemini://example.com/\r\n")
		assertResponse(t, res, "20 text/gemini\r\n")
	})

	t.Run("client certificate not yet valid", func(t *testing.T) {
		clientCert := generateCertificate(t, &x509.Certificate{
			Subject:   pkix.Name{CommonName: "some-client"},
			NotBefore: time.Now().Add(time.Hour),
			NotAfter:  time.Now().Add(2 * time.Hour),
		})

		addr := startServer(t, cert, nil)
		res := sendWithIdentity(t, clientCert, addr, "gemini://example.com/\r\n")
		assertResponse(t, res, "62 Certificate not yet valid\r\n")
	})

	t.Run("client certificate expired", func(t *testing.T) {
		clientCert := generateCertificate(t, &x509.Certificate{
			Subject:   pkix.Name{CommonName: "some-client"},
			NotBefore: time.Now().Add(-2 * time.Hour),
			NotAfter:  time.Now().Add(-time.Hour),
		})

		addr := startServer(t, cert, nil)
		res := sendWithIdentity(t, clientCert, addr, "gemini://example.com/\r\n")
		assertResponse(t, res, "62 Certificate expired\r\n")
	})

	t.Run("client certificate signature invalid", func(t *testing.T) {
		clientCert := generateCertificate(t, &x509.Certificate{
			Subject:   pkix.Name{CommonName: "some-client"},
			NotBefore: time.Now(),
			NotAfter:  time.Now().Add(time.Hour),
		})

		clientCert.Leaf.Signature[0] += 1

		addr := startServer(t, cert, nil)
		res := sendWithIdentity(t, clientCert, addr, "gemini://example.com/\r\n")
		assertResponse(t, res, "62 Invalid signature\r\n")
	})

	t.Run("input expected requires meta", func(t *testing.T) {
		addr := startServer(t, cert, gemini.HandlerFunc(func(r *gemini.Request, w gemini.ResponseWriter) {
			defer assertPanics(t, "sending an input without a prompt")
			w.WriteHeader(gemini.StatusInputExpected, "")
		}))
		send(t, addr, "gemini://example.com/\r\n")
	})

	t.Run("sensitive input expected requires meta", func(t *testing.T) {
		addr := startServer(t, cert, gemini.HandlerFunc(func(r *gemini.Request, w gemini.ResponseWriter) {
			defer assertPanics(t, "sending a sensitive input without a prompt")
			w.WriteHeader(gemini.StatusSensitiveInput, "")
		}))
		send(t, addr, "gemini://example.com/\r\n")
	})

	t.Run("success requires meta", func(t *testing.T) {
		addr := startServer(t, cert, gemini.HandlerFunc(func(r *gemini.Request, w gemini.ResponseWriter) {
			defer assertPanics(t, "sending a success without a media type")
			w.WriteHeader(gemini.StatusSuccess, "")
		}))
		send(t, addr, "gemini://example.com/\r\n")
	})

	t.Run("success requires valid media type", func(t *testing.T) {
		addr := startServer(t, cert, gemini.HandlerFunc(func(r *gemini.Request, w gemini.ResponseWriter) {
			defer assertPanics(t, "invalid media type")
			w.WriteHeader(gemini.StatusSuccess, "not some media type")
		}))
		send(t, addr, "gemini://example.com/\r\n")
	})

	t.Run("temporary redirect requires meta", func(t *testing.T) {
		addr := startServer(t, cert, gemini.HandlerFunc(func(r *gemini.Request, w gemini.ResponseWriter) {
			defer assertPanics(t, "sending a temporary redirection without a URI")
			w.WriteHeader(gemini.StatusTemporaryRedirection, "")
		}))
		send(t, addr, "gemini://example.com/\r\n")
	})

	t.Run("temporary redirect requires valid url", func(t *testing.T) {
		addr := startServer(t, cert, gemini.HandlerFunc(func(r *gemini.Request, w gemini.ResponseWriter) {
			defer assertPanics(t, "invalid URL")
			w.WriteHeader(gemini.StatusTemporaryRedirection, ":")
		}))
		send(t, addr, "gemini://example.com/\r\n")
	})

	t.Run("permanent redirect requires meta", func(t *testing.T) {
		addr := startServer(t, cert, gemini.HandlerFunc(func(r *gemini.Request, w gemini.ResponseWriter) {
			defer assertPanics(t, "sending a permanent redirection without a URI")
			w.WriteHeader(gemini.StatusPermanentRedirection, "")
		}))
		send(t, addr, "gemini://example.com/\r\n")
	})

	t.Run("permanent redirect requires valid url", func(t *testing.T) {
		addr := startServer(t, cert, gemini.HandlerFunc(func(r *gemini.Request, w gemini.ResponseWriter) {
			defer assertPanics(t, "invalid URL")
			w.WriteHeader(gemini.StatusPermanentRedirection, ":")
		}))
		send(t, addr, "gemini://example.com/\r\n")
	})

	t.Run("permanent redirect requires valid url", func(t *testing.T) {
		addr := startServer(t, cert, gemini.HandlerFunc(func(r *gemini.Request, w gemini.ResponseWriter) {
			defer assertPanics(t, "invalid URL path")
			w.WriteHeader(gemini.StatusPermanentRedirection, "relative")
		}))
		send(t, addr, "gemini://example.com/\r\n")
	})
}

func generateCertificate(t *testing.T, template *x509.Certificate) tls.Certificate {
	t.Helper()

	key, err := rsa.GenerateKey(rand.Reader, 1024)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}

	certDER, err := x509.CreateCertificate(rand.Reader, template, template, key.Public(), key)
	if err != nil {
		t.Fatalf("create certificate: %v", err)
	}

	keyPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: x509.MarshalPKCS1PrivateKey(key),
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

func startServer(t *testing.T, cert tls.Certificate, handler gemini.Handler) string {
	t.Helper()

	server := gemini.Server{
		Host:    "localhost",
		Cert:    cert,
		Handler: handler,
	}

	done := make(chan struct{})

	t.Cleanup(func() {
		<-done
	})

	started := make(chan struct{})

	go func() {
		defer close(done)

		close(started)

		if err := server.ListenAndServe(); err != nil {
			t.Errorf("listen and serve: %v", err)
		}
	}()

	<-started

	t.Cleanup(func() {
		if err := server.Close(); err != nil {
			t.Errorf("close: %v", err)
		}
	})

	return server.Addr()
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
