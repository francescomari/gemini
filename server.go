package gemini

import (
	"bufio"
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"io"
	"mime"
	"net"
	"net/url"
	"path"
	"strconv"
	"strings"
	"sync"
	"time"
	"unicode"
)

// DefaultPort is the default port used by the Gemini protocol.
const DefaultPort = 1965

// StatusCode is one of the available status codes.
type StatusCode int

const (
	StatusInputExpected            StatusCode = 10
	StatusSensitiveInput           StatusCode = 11
	StatusSuccess                  StatusCode = 20
	StatusTemporaryRedirection     StatusCode = 30
	StatusPermanentRedirection     StatusCode = 31
	StatusTemporaryFailure         StatusCode = 40
	StatusServerUnavailable        StatusCode = 41
	StatusCGIError                 StatusCode = 42
	StatusProxyError               StatusCode = 43
	StatusSlowDown                 StatusCode = 44
	StatusPermanentFailure         StatusCode = 50
	StatusNotFound                 StatusCode = 51
	StatusGone                     StatusCode = 52
	StatusProxyRequestRefused      StatusCode = 53
	StatusBadRequest               StatusCode = 59
	StatusCertificateRequired      StatusCode = 60
	StatusCertificateNotAuthorized StatusCode = 61
	StatusCertificateNotValid      StatusCode = 62
)

var definedStatusCodes = map[StatusCode]bool{
	StatusInputExpected:            true,
	StatusSensitiveInput:           true,
	StatusSuccess:                  true,
	StatusTemporaryRedirection:     true,
	StatusPermanentRedirection:     true,
	StatusTemporaryFailure:         true,
	StatusServerUnavailable:        true,
	StatusCGIError:                 true,
	StatusProxyError:               true,
	StatusSlowDown:                 true,
	StatusPermanentFailure:         true,
	StatusNotFound:                 true,
	StatusGone:                     true,
	StatusProxyRequestRefused:      true,
	StatusBadRequest:               true,
	StatusCertificateRequired:      true,
	StatusCertificateNotAuthorized: true,
	StatusCertificateNotValid:      true,
}

// Request contains the URL requested by the client.
type Request struct {
	// The URL scheme. It's always "gemini".
	Scheme string
	// The URL host. It's never empty.
	Host string
	// The URL port. It can be zero if the request didn't specify a port, in
	// which case the client expects the default port for the gemini scheme
	// to be used.
	Port int
	// The URL path. It's never empty. If the client didn't include a path in
	// the request, or if the path normalizes to nothing, Path is /.
	//
	// Paths are normalized by removing single-dot components and resolving
	// double-dot components.
	//
	// A trailing / in the original URL path is preserved.
	Path string
	// The query component of the URL. It can be the empty string if not
	// provided.
	Query string
	// The client certificate. It can be nil if the client did not provide a
	// certificate.
	//
	// If the client provides a certificate, the server always validates the
	// not-before, not-after, and signature of the provided certificate.
	// Self-signed certificates are expected and encouraged.
	Cert *x509.Certificate
}

// ResponseWriter generates the server response. A ResponseWriter can't be
// safely used by multiple goroutines.
type ResponseWriter interface {
	io.Writer

	// WriteHeader writes the response header.
	//
	// If response data is written without calling this method, WriteHeader is
	// automatically called with StatusSuccess and a media type
	// of "text/gemini".
	//
	// Calling this method multiple times, or calling this method after
	// response data is written, has no effect.
	//
	// WriteHeader panics if trying to generate a header that does not conform
	// to the specification. For example, StatusSuccess always requires a
	// media type, and StatusInputExpected a prompt.
	WriteHeader(statusCode StatusCode, meta string)
}

// Handler handles client requests and produces responses.
//
// If a handler doesn't write a response header or response data, the server
// automatically sends a StatusSuccess response with media type "text/gemini"
// and no content.
//
// While a handler should deal with its own panics, the server intercepts and
// swallows a panic thrown by a handler. Unless a response has already been sent
// to the client, a panic results in a StatusCGIError response.
type Handler interface {
	Handle(r *Request, w ResponseWriter)
}

// HandlerFunc is an implementation of Handler using a plain function.
type HandlerFunc func(r *Request, w ResponseWriter)

// Handle implements Handler.
func (f HandlerFunc) Handle(r *Request, w ResponseWriter) {
	f(r, w)
}

// Server is a Gemini server. A Server can be safely used by multiple
// goroutines.
type Server struct {
	// The server certificate. Self-signed certificates are supported and
	// encouraged. This field is mandatory.
	Cert tls.Certificate
	// The handler for requests sent to this server. If not provided, the
	// server responds with StatusNotFound to every request that would
	// otherwise be processed by the handler.
	Handler Handler
	// Timeout sets the timeout for each I/O operation performed while serving a
	// connection, be it a read or a write. If not specified, no timeout is set.
	Timeout time.Duration
	// ReadTimeout sets the timeout for each read operation performed while
	// serving a connection. If not specified, no read timeout is set. If both
	// Timeout and ReadTimeout are specified, ReadTimeout overrides Timeout.
	ReadTimeout time.Duration
	// WriteTimeout sets the timeout for each write operation performed while
	// serving a connection. If not specified, no write timeout is set. If both
	// Timeout and WriteTimeout are specified, WriteTimeout overrides Timeout.
	WriteTimeout time.Duration
}

// Serve serves Gemini clients connecting to this server. Serve blocks until
// accepting a connection fails. Before returning, Serve waits until every
// in-flight request is processed and returns the error returned by the
// listener. Serve always returns an error.
func (s *Server) Serve(listener net.Listener) error {
	var wg sync.WaitGroup

	defer wg.Wait()

	for {
		conn, err := listener.Accept()
		if err != nil {
			return err
		}

		wg.Go(func() {
			s.handle(conn)
		})
	}
}

func (s *Server) handle(c net.Conn) {
	var readTimeout time.Duration

	if s.ReadTimeout > 0 {
		readTimeout = s.ReadTimeout
	} else if s.Timeout > 0 {
		readTimeout = s.Timeout
	}

	var writeTimeout time.Duration

	if s.WriteTimeout > 0 {
		writeTimeout = s.WriteTimeout
	} else if s.Timeout > 0 {
		writeTimeout = s.Timeout
	}

	conn := tls.Server(c, &tls.Config{
		Certificates: []tls.Certificate{s.Cert},
		ClientAuth:   tls.RequestClientCert,
		MinVersion:   tls.VersionTLS12,
	})

	defer func() {
		_ = conn.Close()
	}()

	var timeout time.Duration

	if readTimeout > 0 && writeTimeout > 0 {
		timeout = min(readTimeout, writeTimeout)
	} else {
		timeout = max(readTimeout, writeTimeout)
	}

	if timeout > 0 {
		ctx, cancel := context.WithTimeout(context.Background(), timeout)
		defer cancel()

		if err := conn.HandshakeContext(ctx); err != nil {
			return
		}
	} else {
		if err := conn.Handshake(); err != nil {
			return
		}
	}

	var cert *x509.Certificate

	if certs := conn.ConnectionState().PeerCertificates; len(certs) > 0 {
		cert = certs[0]
	}

	if readTimeout > 0 {
		conn.SetReadDeadline(time.Now().Add(readTimeout))
	}

	if writeTimeout > 0 {
		conn.SetWriteDeadline(time.Now().Add(writeTimeout))
	}

	w := responseWriter{
		w: conn,
	}

	defer func() {
		_, _ = w.Write(nil)
	}()

	if cert != nil {
		if time.Now().Before(cert.NotBefore) {
			w.WriteHeader(StatusCertificateNotValid, "Certificate not yet valid")
			return
		}

		if cert.NotAfter.Before(time.Now()) {
			w.WriteHeader(StatusCertificateNotValid, "Certificate expired")
			return
		}

		if err := cert.CheckSignature(cert.SignatureAlgorithm, cert.RawTBSCertificate, cert.Signature); err != nil {
			w.WriteHeader(StatusCertificateNotValid, "Invalid signature")
			return
		}
	}

	data, err := bufio.NewReader(io.LimitReader(conn, 1024+1+1)).ReadBytes('\n')

	if err != nil {
		if errors.Is(err, io.EOF) {
			w.WriteHeader(StatusBadRequest, "Request is too long")
		} else {
			w.WriteHeader(StatusTemporaryFailure, "Unable to read")
		}
		return
	}

	if !bytes.HasSuffix(data, []byte{'\r', '\n'}) {
		w.WriteHeader(StatusBadRequest, "Request is malformed")
		return
	}

	if len(data) < 3 {
		w.WriteHeader(StatusBadRequest, "Request is too short")
		return
	}

	parsed, err := url.Parse(string(data[0 : len(data)-2]))
	if err != nil {
		w.WriteHeader(StatusBadRequest, "The URL is malformed")
		return
	}

	if parsed.Scheme == "" {
		w.WriteHeader(StatusBadRequest, "The URL has no scheme")
		return
	}

	if parsed.Scheme != "gemini" {
		w.WriteHeader(StatusProxyRequestRefused, "Unsupported protocol")
		return
	}

	host := parsed.Hostname()

	if host == "" {
		w.WriteHeader(StatusBadRequest, "The URL has no host")
		return
	}

	path := cleanPath(parsed.Path)

	for _, c := range path {
		if unicode.Is(unicode.C, c) {
			w.WriteHeader(StatusBadRequest, "The URL path contains control characters")
			return
		}
	}

	if parsed.User != nil {
		w.WriteHeader(StatusBadRequest, "The URL has user info")
		return
	}

	if parsed.Fragment != "" {
		w.WriteHeader(StatusBadRequest, "The URL has a fragment")
		return
	}

	if s.Handler == nil {
		w.WriteHeader(StatusNotFound, "")
		return
	}

	port, _ := strconv.Atoi(parsed.Port())

	request := Request{
		Scheme: parsed.Scheme,
		Host:   host,
		Port:   port,
		Path:   path,
		Query:  parsed.RawQuery,
		Cert:   cert,
	}

	s.callHandler(&request, &w)
}

func (s *Server) callHandler(r *Request, w ResponseWriter) {
	defer func() {
		if v := recover(); v != nil {
			w.WriteHeader(StatusCGIError, "Panic")
		}
	}()

	s.Handler.Handle(r, w)
}

type responseWriter struct {
	w      io.Writer
	header bool
}

func (w *responseWriter) Write(p []byte) (int, error) {
	w.WriteHeader(StatusSuccess, "text/gemini")
	return w.w.Write(p)
}

func (w *responseWriter) WriteHeader(statusCode StatusCode, meta string) {
	if !w.header {
		w.validateMeta(statusCode, meta)

		if meta == "" {
			fmt.Fprintf(w.w, "%2d\r\n", statusCode)
		} else {
			fmt.Fprintf(w.w, "%2d %s\r\n", statusCode, meta)
		}

		w.header = true
	}
}

func (w *responseWriter) validateMeta(statusCode StatusCode, meta string) {
	if !definedStatusCodes[statusCode] {
		panic("invalid status code")
	}

	if meta == "" {
		switch statusCode {
		case StatusInputExpected:
			panic("sending an input without a prompt")
		case StatusSensitiveInput:
			panic("sending a sensitive input without a prompt")
		case StatusSuccess:
			panic("sending a success without a media type")
		case StatusTemporaryRedirection:
			panic("sending a temporary redirection without a URI")
		case StatusPermanentRedirection:
			panic("sending a permanent redirection without a URI")
		}
	} else {
		w.validateControlCharacters(meta)

		switch statusCode {
		case StatusSuccess:
			w.validateMediaType(meta)
		case StatusTemporaryRedirection:
			w.validateURI(meta)
		case StatusPermanentRedirection:
			w.validateURI(meta)
		}
	}
}

func (w *responseWriter) validateControlCharacters(s string) {
	for _, c := range s {
		if unicode.Is(unicode.C, c) {
			panic("meta contains control characters")
		}
	}
}

func (w *responseWriter) validateMediaType(s string) {
	if _, _, err := mime.ParseMediaType(s); err != nil {
		panic("invalid media type")
	}
}

func (w *responseWriter) validateURI(s string) {
	if _, err := url.Parse(s); err != nil {
		panic("invalid URI")
	}
}

func cleanPath(in string) string {
	out := path.Clean(in)

	if out == "." {
		return "/"
	}

	if out == "/" {
		return out
	}

	if strings.HasSuffix(in, "/") {
		return out + "/"
	}

	return out
}
