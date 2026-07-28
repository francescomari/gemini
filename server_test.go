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

	t.Run("request too long", func(t *testing.T) {
		addr := startServer(t, cert, handlerShouldNotBeCalled(t))
		res := sendAnonymous(t, addr, fmt.Sprintf("/%s\r\n", strings.Repeat("x", 1024)))
		require.Equal(t, "59 Request is too long\r\n", res)
	})

	t.Run("request malformed", func(t *testing.T) {
		addr := startServer(t, cert, handlerShouldNotBeCalled(t))
		res := sendAnonymous(t, addr, "gemini://example.com/\n")
		require.Equal(t, "59 Request is malformed\r\n", res)
	})

	t.Run("request too short", func(t *testing.T) {
		addr := startServer(t, cert, handlerShouldNotBeCalled(t))
		res := sendAnonymous(t, addr, "\r\n")
		require.Equal(t, "59 Request is too short\r\n", res)
	})

	t.Run("malformed url", func(t *testing.T) {
		addr := startServer(t, cert, handlerShouldNotBeCalled(t))
		res := sendAnonymous(t, addr, ":\r\n")
		require.Equal(t, "59 The URL is malformed\r\n", res)
	})

	t.Run("no scheme", func(t *testing.T) {
		addr := startServer(t, cert, handlerShouldNotBeCalled(t))
		res := sendAnonymous(t, addr, "//example.com/path\r\n")
		require.Equal(t, "59 The URL has no scheme\r\n", res)
	})

	t.Run("unsupported scheme", func(t *testing.T) {
		addr := startServer(t, cert, handlerShouldNotBeCalled(t))
		res := sendAnonymous(t, addr, "https://example.com/path\r\n")
		require.Equal(t, "53 Unsupported protocol\r\n", res)
	})

	t.Run("no host", func(t *testing.T) {
		addr := startServer(t, cert, handlerShouldNotBeCalled(t))
		res := sendAnonymous(t, addr, "gemini:///path\r\n")
		require.Equal(t, "59 The URL has no host\r\n", res)
	})

	t.Run("path with control characters", func(t *testing.T) {
		addr := startServer(t, cert, handlerShouldNotBeCalled(t))
		res := sendAnonymous(t, addr, "gemini://example.com/x%0Ax\r\n")
		require.Equal(t, "59 The URL path contains control characters\r\n", res)
	})

	t.Run("user info", func(t *testing.T) {
		addr := startServer(t, cert, handlerShouldNotBeCalled(t))
		res := sendAnonymous(t, addr, "gemini://user@example.com/path\r\n")
		require.Equal(t, "59 The URL has user info\r\n", res)
	})

	t.Run("fragment", func(t *testing.T) {
		addr := startServer(t, cert, handlerShouldNotBeCalled(t))
		res := sendAnonymous(t, addr, "gemini://example.com/path#fragment\r\n")
		require.Equal(t, "59 The URL has a fragment\r\n", res)
	})

	t.Run("handler", func(t *testing.T) {
		addr := startServer(t, cert, gemini.HandlerFunc(func(ctx context.Context, r *gemini.Request, w gemini.ResponseWriter) {
			assert.NotNil(t, ctx)
			assert.Equal(t, "gemini", r.Scheme)
			assert.Equal(t, "example.com", r.Host)
			assert.Equal(t, 1234, r.Port)
			assert.Equal(t, "/path", r.Path)
			assert.Equal(t, "query", r.Query)
			assert.Nil(t, r.Cert)
			w.Write([]byte("Some text\r\n"))
		}))
		res := sendAnonymous(t, addr, "gemini://example.com:1234/path?query\r\n")
		require.Equal(t, "20 text/gemini\r\nSome text\r\n", res)
	})

	t.Run("empty path is normalized", func(t *testing.T) {
		addr := startServer(t, cert, gemini.HandlerFunc(func(ctx context.Context, r *gemini.Request, w gemini.ResponseWriter) {
			assert.Equal(t, "/", r.Path)
		}))
		sendAnonymous(t, addr, "gemini://example.com\r\n")
	})

	t.Run("final slash is preserved", func(t *testing.T) {
		addr := startServer(t, cert, gemini.HandlerFunc(func(ctx context.Context, r *gemini.Request, w gemini.ResponseWriter) {
			assert.Equal(t, "/foo/", r.Path)
		}))
		sendAnonymous(t, addr, "gemini://example.com/foo/\r\n")
	})

	t.Run("client certificate", func(t *testing.T) {
		addr := startServer(t, cert, gemini.HandlerFunc(func(ctx context.Context, r *gemini.Request, w gemini.ResponseWriter) {
			assert.NotNil(t, r.Cert)
			assert.Equal(t, "client", r.Cert.Subject.CommonName)
		}))
		res := sendWithIdentity(t, newClientCertificate(t), addr, "gemini://example.com/\r\n")
		require.Equal(t, "20 text/gemini\r\n", res)
	})

	t.Run("client certificate not yet valid", func(t *testing.T) {
		addr := startServer(t, cert, handlerShouldNotBeCalled(t))
		res := sendWithIdentity(t, newClientCertificateNotYetValid(t), addr, "gemini://example.com/\r\n")
		require.Equal(t, "62 Certificate not yet valid\r\n", res)
	})

	t.Run("client certificate expired", func(t *testing.T) {
		addr := startServer(t, cert, handlerShouldNotBeCalled(t))
		res := sendWithIdentity(t, newClientCertificateExpired(t), addr, "gemini://example.com/\r\n")
		require.Equal(t, "62 Certificate expired\r\n", res)
	})

	t.Run("client certificate signature invalid", func(t *testing.T) {
		addr := startServer(t, cert, handlerShouldNotBeCalled(t))
		res := sendWithIdentity(t, newClientCertificateInvalidSignature(t), addr, "gemini://example.com/\r\n")
		require.Equal(t, "62 Invalid signature\r\n", res)
	})

	t.Run("status code too low", func(t *testing.T) {
		addr := startServer(t, cert, gemini.HandlerFunc(func(ctx context.Context, r *gemini.Request, w gemini.ResponseWriter) {
			defer assertPanics(t, "invalid status code")
			w.WriteHeader(9, "")
		}))
		sendAnonymous(t, addr, "gemini://example.com/\r\n")
	})

	t.Run("status code too high", func(t *testing.T) {
		addr := startServer(t, cert, gemini.HandlerFunc(func(ctx context.Context, r *gemini.Request, w gemini.ResponseWriter) {
			defer assertPanics(t, "invalid status code")
			w.WriteHeader(70, "")
		}))
		sendAnonymous(t, addr, "gemini://example.com/\r\n")
	})

	t.Run("status code in range but undefined", func(t *testing.T) {
		addr := startServer(t, cert, gemini.HandlerFunc(func(ctx context.Context, r *gemini.Request, w gemini.ResponseWriter) {
			defer assertPanics(t, "invalid status code")
			w.WriteHeader(21, "")
		}))
		sendAnonymous(t, addr, "gemini://example.com/\r\n")
	})

	t.Run("meta with control characters", func(t *testing.T) {
		addr := startServer(t, cert, gemini.HandlerFunc(func(ctx context.Context, r *gemini.Request, w gemini.ResponseWriter) {
			defer assertPanics(t, "meta contains control characters")
			w.WriteHeader(gemini.StatusTemporaryFailure, "x\nx")
		}))
		sendAnonymous(t, addr, "gemini://example.com/\r\n")
	})

	t.Run("input expected requires meta", func(t *testing.T) {
		addr := startServer(t, cert, gemini.HandlerFunc(func(ctx context.Context, r *gemini.Request, w gemini.ResponseWriter) {
			defer assertPanics(t, "sending an input without a prompt")
			w.WriteHeader(gemini.StatusInputExpected, "")
		}))
		sendAnonymous(t, addr, "gemini://example.com/\r\n")
	})

	t.Run("sensitive input expected requires meta", func(t *testing.T) {
		addr := startServer(t, cert, gemini.HandlerFunc(func(ctx context.Context, r *gemini.Request, w gemini.ResponseWriter) {
			defer assertPanics(t, "sending a sensitive input without a prompt")
			w.WriteHeader(gemini.StatusSensitiveInput, "")
		}))
		sendAnonymous(t, addr, "gemini://example.com/\r\n")
	})

	t.Run("success requires meta", func(t *testing.T) {
		addr := startServer(t, cert, gemini.HandlerFunc(func(ctx context.Context, r *gemini.Request, w gemini.ResponseWriter) {
			defer assertPanics(t, "sending a success without a media type")
			w.WriteHeader(gemini.StatusSuccess, "")
		}))
		sendAnonymous(t, addr, "gemini://example.com/\r\n")
	})

	t.Run("success requires valid media type", func(t *testing.T) {
		addr := startServer(t, cert, gemini.HandlerFunc(func(ctx context.Context, r *gemini.Request, w gemini.ResponseWriter) {
			defer assertPanics(t, "invalid media type")
			w.WriteHeader(gemini.StatusSuccess, "not some media type")
		}))
		sendAnonymous(t, addr, "gemini://example.com/\r\n")
	})

	t.Run("temporary redirect requires meta", func(t *testing.T) {
		addr := startServer(t, cert, gemini.HandlerFunc(func(ctx context.Context, r *gemini.Request, w gemini.ResponseWriter) {
			defer assertPanics(t, "sending a temporary redirection without a URI")
			w.WriteHeader(gemini.StatusTemporaryRedirection, "")
		}))
		sendAnonymous(t, addr, "gemini://example.com/\r\n")
	})

	t.Run("temporary redirect requires valid url", func(t *testing.T) {
		addr := startServer(t, cert, gemini.HandlerFunc(func(ctx context.Context, r *gemini.Request, w gemini.ResponseWriter) {
			defer assertPanics(t, "invalid URL")
			w.WriteHeader(gemini.StatusTemporaryRedirection, ":")
		}))
		sendAnonymous(t, addr, "gemini://example.com/\r\n")
	})

	t.Run("permanent redirect requires meta", func(t *testing.T) {
		addr := startServer(t, cert, gemini.HandlerFunc(func(ctx context.Context, r *gemini.Request, w gemini.ResponseWriter) {
			defer assertPanics(t, "sending a permanent redirection without a URI")
			w.WriteHeader(gemini.StatusPermanentRedirection, "")
		}))
		sendAnonymous(t, addr, "gemini://example.com/\r\n")
	})

	t.Run("permanent redirect requires valid url", func(t *testing.T) {
		addr := startServer(t, cert, gemini.HandlerFunc(func(ctx context.Context, r *gemini.Request, w gemini.ResponseWriter) {
			defer assertPanics(t, "invalid URL")
			w.WriteHeader(gemini.StatusPermanentRedirection, ":")
		}))
		sendAnonymous(t, addr, "gemini://example.com/\r\n")
	})

	t.Run("panic handling", func(t *testing.T) {
		addr := startServer(t, cert, gemini.HandlerFunc(func(ctx context.Context, r *gemini.Request, w gemini.ResponseWriter) {
			panic("something went wrong")
		}))
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

func assertPanics(t *testing.T, expected string) {
	s, ok := recover().(string)

	if assert.True(t, ok) {
		assert.Equal(t, s, expected)
	}
}
