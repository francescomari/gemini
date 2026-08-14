package gemini

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
	"sync"
	"testing"
	"testing/synctest"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestReadTimeoutTLS(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		sp, cp := net.Pipe()
		defer sp.Close()
		defer cp.Close()

		server := Server{
			Cert:        newServerCertificate(t),
			ReadTimeout: 10 * time.Second,
		}

		start := time.Now()
		server.handle(sp)
		require.Equal(t, server.ReadTimeout, time.Since(start))
	})
}

func TestReadTimeoutOverTimeoutTLS(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		sp, cp := net.Pipe()
		defer sp.Close()
		defer cp.Close()

		server := Server{
			Cert:        newServerCertificate(t),
			ReadTimeout: 10 * time.Second,
			Timeout:     20 * time.Second,
		}

		start := time.Now()
		server.handle(sp)
		require.Equal(t, server.ReadTimeout, time.Since(start))
	})
}

func TestWriteTimeoutTLS(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		sp, cp := net.Pipe()
		defer sp.Close()
		defer cp.Close()

		server := Server{
			Cert:         newServerCertificate(t),
			WriteTimeout: 10 * time.Second,
		}

		start := time.Now()
		server.handle(sp)
		require.Equal(t, server.WriteTimeout, time.Since(start))
	})
}

func TestWriteTimeoutOverTimeoutTLS(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		sp, cp := net.Pipe()
		defer sp.Close()
		defer cp.Close()

		server := Server{
			Cert:         newServerCertificate(t),
			WriteTimeout: 10 * time.Second,
			Timeout:      20 * time.Second,
		}

		start := time.Now()
		server.handle(sp)
		require.Equal(t, server.WriteTimeout, time.Since(start))
	})
}

func TestSmallerTimeoutTLS(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		sp, cp := net.Pipe()
		defer sp.Close()
		defer cp.Close()

		server := Server{
			Cert:         newServerCertificate(t),
			ReadTimeout:  10 * time.Second,
			WriteTimeout: 20 * time.Second,
			Timeout:      30 * time.Second,
		}

		start := time.Now()
		server.handle(sp)
		require.Equal(t, server.ReadTimeout, time.Since(start))
	})
}

func TestReadTimeout(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		sp, cp := net.Pipe()
		defer sp.Close()

		server := Server{
			Cert:        newServerCertificate(t),
			ReadTimeout: 10 * time.Second,
		}

		conn := tls.Client(cp, &tls.Config{InsecureSkipVerify: true})
		defer conn.Close()

		server.handle(sp)
	})
}

func TestReadTimeoutOverTimeout(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		sp, cp := net.Pipe()
		defer sp.Close()

		server := Server{
			Cert:        newServerCertificate(t),
			ReadTimeout: 10 * time.Second,
			Timeout:     20 * time.Second,
		}

		conn := tls.Client(cp, &tls.Config{InsecureSkipVerify: true})
		defer conn.Close()

		server.handle(sp)
	})
}

func TestWriteTimeout(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		sp, cp := net.Pipe()
		defer sp.Close()

		server := Server{
			Cert:         newServerCertificate(t),
			WriteTimeout: 10 * time.Second,
		}

		conn := tls.Client(cp, &tls.Config{InsecureSkipVerify: true})
		defer conn.Close()

		go func() {
			conn.Write([]byte("gemini://example.com\r\n"))
		}()

		server.handle(sp)
	})
}

func TestWriteTimeoutOverTimeout(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		sp, cp := net.Pipe()
		defer sp.Close()

		server := Server{
			Cert:         newServerCertificate(t),
			WriteTimeout: 10 * time.Second,
			Timeout:      20 * time.Second,
		}

		conn := tls.Client(cp, &tls.Config{InsecureSkipVerify: true})
		defer conn.Close()

		go func() {
			conn.Write([]byte("gemini://example.com\r\n"))
		}()

		server.handle(sp)
	})
}
func TestNoHandler(t *testing.T) {
	addr := startServer(t, nil)
	res := sendAnonymous(t, addr, "gemini://example.com/path\r\n")
	require.Equal(t, "51\r\n", res)
}

func TestServerValidation(t *testing.T) {
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
			addr := startServer(t, handlerShouldNotBeCalled(t))
			res := sendAnonymous(t, addr, test.request)
			require.Equal(t, test.response, res)
		})
	}
}

func TestHandler(t *testing.T) {
	handler := HandlerFunc(func(ctx context.Context, w ResponseWriter, r *Request) {
		assert.Equal(t, "gemini", r.Scheme)
		assert.Equal(t, "example.com", r.Host)
		assert.Equal(t, 1234, r.Port)
		assert.Equal(t, "/path", r.Path)
		assert.Equal(t, "query", r.Query)
		assert.Nil(t, r.Cert)
		assert.NotEmpty(t, r.RemoteAddr)
		w.Write([]byte("Some text\r\n"))
	})
	addr := startServer(t, handler)
	res := sendAnonymous(t, addr, "gemini://example.com:1234/path?query\r\n")
	require.Equal(t, "20 text/gemini\r\nSome text\r\n", res)
}

func TestEmptyPath(t *testing.T) {
	handler := HandlerFunc(func(ctx context.Context, w ResponseWriter, r *Request) {
		assert.Equal(t, "/", r.Path)
	})
	addr := startServer(t, handler)
	sendAnonymous(t, addr, "gemini://example.com\r\n")
}

func TestSlashSuffix(t *testing.T) {
	handler := HandlerFunc(func(ctx context.Context, w ResponseWriter, r *Request) {
		assert.Equal(t, "/foo/", r.Path)
	})
	addr := startServer(t, handler)
	sendAnonymous(t, addr, "gemini://example.com/foo/\r\n")
}

func TestClientCertificate(t *testing.T) {
	handler := HandlerFunc(func(ctx context.Context, w ResponseWriter, r *Request) {
		assert.NotNil(t, r.Cert)
		assert.Equal(t, "client", r.Cert.Subject.CommonName)
	})
	addr := startServer(t, handler)
	res := sendAuthenticated(t, newClientCertificate(t), addr, "gemini://example.com/\r\n")
	require.Equal(t, "20 text/gemini\r\n", res)
}

func TestClientCertificateValidation(t *testing.T) {
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
			addr := startServer(t, handlerShouldNotBeCalled(t))
			res := sendAuthenticated(t, test.cert, addr, "gemini://example.com/\r\n")
			require.Equal(t, test.response, res)
		})
	}
}

func TestResponseWriterValidation(t *testing.T) {
	tests := []struct {
		name       string
		statusCode StatusCode
		meta       string
		value      string
	}{
		{"status code too low", 9, "", "invalid status code"},
		{"status code too high", 70, "", "invalid status code"},
		{"unspecified status code", 21, "", "invalid status code"},
		{"control characters", StatusTemporaryFailure, "\n", "meta contains control characters"},
		{"input without meta", StatusInputExpected, "", "sending an input without a prompt"},
		{"sensitive input without meta", StatusSensitiveInput, "", "sending a sensitive input without a prompt"},
		{"success without media type", StatusSuccess, "", "sending a success without a media type"},
		{"invalid media type", StatusSuccess, "not a media type", "invalid media type"},
		{"temporary redirection without uri", StatusTemporaryRedirection, "", "sending a temporary redirection without a URI"},
		{"permanent redirection without uri", StatusPermanentRedirection, "", "sending a permanent redirection without a URI"},
		{"temporary redirection with invalid uri", StatusTemporaryRedirection, ":", "invalid URI"},
		{"permanent redirection with invalid uri", StatusPermanentRedirection, ":", "invalid URI"},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			handler := HandlerFunc(func(ctx context.Context, w ResponseWriter, r *Request) {
				assert.PanicsWithValue(t, test.value, func() {
					w.WriteHeader(test.statusCode, test.meta)
				})
			})
			addr := startServer(t, handler)
			sendAnonymous(t, addr, "gemini://example.com/\r\n")
		})
	}
}

func TestPanic(t *testing.T) {
	handler := HandlerFunc(func(ctx context.Context, w ResponseWriter, r *Request) {
		panic("something went wrong")
	})
	addr := startServer(t, handler)
	res := sendAnonymous(t, addr, "gemini://example.com/\r\n")
	require.Equal(t, "42 Panic\r\n", res)
}

func handlerShouldNotBeCalled(t *testing.T) HandlerFunc {
	return func(ctx context.Context, w ResponseWriter, r *Request) {
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

func startServer(t *testing.T, handler Handler) string {
	t.Helper()

	var wg sync.WaitGroup

	t.Cleanup(func() {
		wg.Wait()
	})

	listener, err := net.Listen("tcp", net.JoinHostPort("localhost", "0"))
	if err != nil {
		t.Fatalf("listen: %v", err)
	}

	t.Cleanup(func() {
		if err := listener.Close(); err != nil {
			t.Errorf("close: %v", err)
		}
	})

	wg.Go(func() {
		server := Server{
			Cert:    newServerCertificate(t),
			Handler: handler,
		}

		if err := server.Serve(listener); !errors.Is(err, net.ErrClosed) {
			t.Errorf("serve: %v", err)
		}
	})

	return listener.Addr().String()
}

func sendAnonymous(t *testing.T, addr string, request string) string {
	t.Helper()

	config := tls.Config{
		InsecureSkipVerify: true,
	}

	return send(t, &config, addr, request)
}

func sendAuthenticated(t *testing.T, cert tls.Certificate, addr string, request string) string {
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
