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
// The context passed to the handler is derived from the context passed to
// [Server.ListenAndServe]. The context passed to the handler will always be
// cancelled during the shutdown of a server.
//
// While a handler should deal with its own panics, the server intercepts
// and swallows a panic thrown by a handler. Unless a response has already
// been sent to the client, panics result in StatusCGIError responses.
type Handler interface {
	Handle(ctx context.Context, r *Request, w ResponseWriter)
}

// HandlerFunc is an implementation of Handler using a plain function.
type HandlerFunc func(ctx context.Context, r *Request, w ResponseWriter)

// Handle implements Handler.
func (f HandlerFunc) Handle(ctx context.Context, r *Request, w ResponseWriter) {
	f(ctx, r, w)
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
	// Timeout sets the timeout for each read and write operation performed by
	// a single request. If not specified, no timeout is set.
	Timeout time.Duration
	// ReadTimeout sets the timeout for read operations performed by a single
	// request. If not specified, no read timeout is set. If both Timeout and
	// ReadTimeout are specified, ReadTimeout overrides Timeout.
	ReadTimeout time.Duration
	// WriteTimeout sets the timeout for write operations performed by a
	// single request. If not specified, no write timeout is set. If both
	// Timeout and WriteTimeout are specified, WriteTimeout overrides Timeout.
	WriteTimeout time.Duration
}

// Serve wraps the provided listener in a TLS listener and serves Gemini clients
// connecting to this server. Serve blocks until the context is cancelled or
// accepting a connection fails. In both cases, Serve waits until every
// in-flight request is processed and returns a non-nil error wrapping the
// cause. Callers can use errors.Is(err, context.Canceled) to distinguish a
// deliberate shutdown from an accept failure. Serve always returns an error.
func (s *Server) Serve(ctx context.Context, listener net.Listener) error {
	listener = tls.NewListener(listener, &tls.Config{
		Certificates: []tls.Certificate{s.Cert},
		ClientAuth:   tls.RequestClientCert,
		MinVersion:   tls.VersionTLS12,
	})

	defer func() {
		_ = listener.Close()
	}()

	var wg sync.WaitGroup

	defer wg.Wait()

	ctx, cancel := context.WithCancel(ctx)
	defer cancel()

	for {
		conn, err := s.accept(ctx, listener)
		if err != nil {
			return fmt.Errorf("accept: %w", err)
		}

		wg.Go(func() {
			s.handle(ctx, conn)
		})
	}
}

func (s *Server) accept(ctx context.Context, listener net.Listener) (net.Conn, error) {
	type result struct {
		conn net.Conn
		err  error
	}

	ch := make(chan result)

	go func() {
		conn, err := listener.Accept()

		select {
		case ch <- result{conn, err}:
		case <-ctx.Done():
			if err == nil {
				_ = conn.Close()
			}
		}
	}()

	select {
	case result := <-ch:
		return result.conn, result.err
	case <-ctx.Done():
		return nil, ctx.Err()
	}
}

func (s *Server) handle(ctx context.Context, conn net.Conn) {
	defer func() {
		_ = conn.Close()
	}()

	if s.ReadTimeout > 0 {
		conn.SetReadDeadline(time.Now().Add(s.ReadTimeout))
	} else if s.Timeout > 0 {
		conn.SetReadDeadline(time.Now().Add(s.Timeout))
	}

	data, err := bufio.NewReader(io.LimitReader(conn, 1024+1+1)).ReadBytes('\n')

	if s.WriteTimeout > 0 {
		conn.SetWriteDeadline(time.Now().Add(s.WriteTimeout))
	} else if s.Timeout > 0 {
		conn.SetWriteDeadline(time.Now().Add(s.Timeout))
	}

	if err != nil {
		if errors.Is(err, io.EOF) {
			writeHeader(conn, StatusBadRequest, "Request is too long")
		} else {
			writeHeader(conn, StatusTemporaryFailure, "Unable to read")
		}
		return
	}

	if !bytes.HasSuffix(data, []byte{'\r', '\n'}) {
		writeHeader(conn, StatusBadRequest, "Request is malformed")
		return
	}

	if len(data) < 3 {
		writeHeader(conn, StatusBadRequest, "Request is too short")
		return
	}

	parsed, err := url.Parse(string(data[0 : len(data)-2]))
	if err != nil {
		writeHeader(conn, StatusBadRequest, "The URL is malformed")
		return
	}

	if parsed.Scheme == "" {
		writeHeader(conn, StatusBadRequest, "The URL has no scheme")
		return
	}

	if parsed.Scheme != "gemini" {
		writeHeader(conn, StatusProxyRequestRefused, "Unsupported protocol")
		return
	}

	host := parsed.Hostname()

	if host == "" {
		writeHeader(conn, StatusBadRequest, "The URL has no host")
		return
	}

	path := cleanPath(parsed.Path)

	for _, c := range path {
		if unicode.Is(unicode.C, c) {
			writeHeader(conn, StatusBadRequest, "The URL path contains control characters")
			return
		}
	}

	if parsed.User != nil {
		writeHeader(conn, StatusBadRequest, "The URL has user info")
		return
	}

	if parsed.Fragment != "" {
		writeHeader(conn, StatusBadRequest, "The URL has a fragment")
		return
	}

	cert, err := s.readCertificate(conn.(*tls.Conn))
	if err != nil {
		return
	}

	if cert != nil {
		if time.Now().Before(cert.NotBefore) {
			writeHeader(conn, StatusCertificateNotValid, "Certificate not yet valid")
			return
		}

		if cert.NotAfter.Before(time.Now()) {
			writeHeader(conn, StatusCertificateNotValid, "Certificate expired")
			return
		}

		if err := cert.CheckSignature(cert.SignatureAlgorithm, cert.RawTBSCertificate, cert.Signature); err != nil {
			writeHeader(conn, StatusCertificateNotValid, "Invalid signature")
			return
		}
	}

	if s.Handler == nil {
		writeHeader(conn, StatusNotFound, "")
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

	responseWriter := responseWriter{
		w: conn,
	}

	s.callHandler(ctx, &request, &responseWriter)

	responseWriter.writeDefaultHeader()
}

func (s *Server) callHandler(ctx context.Context, r *Request, w ResponseWriter) {
	defer func() {
		if v := recover(); v != nil {
			w.WriteHeader(StatusCGIError, "Panic")
		}
	}()

	s.Handler.Handle(ctx, r, w)
}

func (s *Server) readCertificate(conn *tls.Conn) (*x509.Certificate, error) {
	if err := conn.Handshake(); err != nil {
		return nil, fmt.Errorf("handshake: %v", err)
	}

	if certs := conn.ConnectionState().PeerCertificates; len(certs) > 0 {
		return certs[0], nil
	}

	return nil, nil
}

type responseWriter struct {
	w      io.Writer
	header bool
}

func (rw *responseWriter) Write(p []byte) (int, error) {
	if !rw.header {
		rw.writeDefaultHeader()
	}

	return rw.w.Write(p)
}

func (rw *responseWriter) WriteHeader(statusCode StatusCode, meta string) {
	if !rw.header {
		rw.validateMeta(statusCode, meta)
		writeHeader(rw.w, statusCode, meta)
		rw.header = true
	}
}

func (rw *responseWriter) writeDefaultHeader() {
	rw.WriteHeader(StatusSuccess, "text/gemini")
}

func (rw *responseWriter) validateMeta(statusCode StatusCode, meta string) {
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
		rw.validateControlCharacters(meta)

		switch statusCode {
		case StatusSuccess:
			rw.validateMediaType(meta)
		case StatusTemporaryRedirection:
			rw.validateURI(meta)
		case StatusPermanentRedirection:
			rw.validateURI(meta)
		}
	}
}

func (rw *responseWriter) validateControlCharacters(s string) {
	for _, c := range s {
		if unicode.Is(unicode.C, c) {
			panic("meta contains control characters")
		}
	}
}

func (rw *responseWriter) validateMediaType(s string) {
	if _, _, err := mime.ParseMediaType(s); err != nil {
		panic("invalid media type")
	}
}

func (rw *responseWriter) validateURI(s string) {
	if _, err := url.Parse(s); err != nil {
		panic("invalid URI")
	}
}

func writeHeader(w io.Writer, statusCode StatusCode, meta string) {
	if meta == "" {
		fmt.Fprintf(w, "%2d\r\n", statusCode)
	} else {
		fmt.Fprintf(w, "%2d %s\r\n", statusCode, meta)
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
