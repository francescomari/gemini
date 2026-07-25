package gemini

import (
	"bufio"
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
)

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
	StatusCerttificateNotValid     StatusCode = 62
)

// Request contains the URL requested by the client.
type Request struct {
	// The URL scheme. It can be the empty string if the request did not
	// contain a scheme, for example when the client requested an aboslute
	// path.
	Scheme string
	// The URL host. It can be the empty string if the request did not contain
	// a scheme, for example when the client requested an absolute path.
	Host string
	// The URL port. It can be zero if the request did not contain a port, for
	// example when the user requested an aboslute path or when the user
	// expectes to use the default port for the requested scheme.
	Port int
	// The URL path. It's never empty. If the user didn't include a path in
	// the request, Path is /.
	//
	// Paths are normalized by removing single-dot path components and
	// processing double-dots path components. If, after normalization, the
	// path is too short, Path is /.
	//
	// Any trailing / from the URL path is presrved.
	Path string
	// The query component of the URL. It can be the empty string if not
	// provided.
	Query string
	// The client certificate. It can be nil if the client did not provide a
	// certificate.
	//
	// If the client provides a certificate, the client always validates the
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
	// to the specification. For example, StatusSuccess always require a URL,
	// and StatusInputExpected a prompt.
	WriteHeader(statusCode StatusCode, meta string)
}

// Handler handles client requests and produces responses.
//
// If a handler doesn't write a response header or response data, the server
// automatically sends a StatusSuccess response with media type "text/gemini"
// and no content.
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
	// The host this server will listen at. If not provided, the server
	// listens on all available interfaces on the system.
	Host string
	// The port this server will listen at. If not provided, the server listes
	// on a randomly allocated port.
	Port int
	// The server certificate. Self-signed certificates are supported and
	// encouraged. This field is mandatory.
	Cert tls.Certificate
	// The handler for requests sent to this server. If not provided, the
	// server responds with StatusNotFound to every request that would
	// otherwise be processed by the handler.
	Handler Handler
	// Timeout sets the timeout for each read and write operations performed
	// by a single request. If not specified, no timeout is set.
	Timeout time.Duration
	// ReadTimeout sets the timeout for read operations performed by a single
	// request. If not specified, no read timeout is set.
	ReadTimeout time.Duration
	// WriteTimeout sets the timeout for write operations performed by a
	// single request. If not specified, no read timeout is set.
	WriteTimeout time.Duration

	mu       sync.Mutex
	listener net.Listener
	wg       sync.WaitGroup
}

// ListenAndServe starts a TLS connection over TCP, and serves Gemini clients
// connecting to this server. Returns an error if a failure occurred when
// setting up the server. ListenAndServer blocks until the server is closed
// and any in-flight request is processed.
func (s *Server) ListenAndServe() error {
	if err := s.listen(); err != nil {
		return fmt.Errorf("listen: %v", err)
	}

	if err := s.serve(); err != nil {
		return fmt.Errorf("serve: %v", err)
	}

	return nil
}

// Close stops the server. Returns an error if the server is not listening.
func (s *Server) Close() error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if s.listener == nil {
		return fmt.Errorf("server not listening")
	}

	listener := s.listener
	s.listener = nil

	return listener.Close()
}

// Addr returns the address of this server. If the server is not listening,
// returns the empty string.
func (s *Server) Addr() string {
	s.mu.Lock()
	defer s.mu.Unlock()

	if s.listener != nil {
		return s.listener.Addr().String()
	}

	return ""
}

func (s *Server) listen() error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if s.listener != nil {
		return fmt.Errorf("server already started")
	}

	config := tls.Config{
		Certificates: []tls.Certificate{s.Cert},
		ClientAuth:   tls.RequestClientCert,
	}

	listener, err := tls.Listen("tcp", s.addr(), &config)
	if err != nil {
		return fmt.Errorf("listen: %v", err)
	}

	s.listener = listener

	return nil
}

func (s *Server) addr() string {
	return net.JoinHostPort(s.Host, strconv.Itoa(s.Port))
}

func (s *Server) serve() error {
	s.mu.Lock()
	listener := s.listener
	s.mu.Unlock()

	if listener == nil {
		return fmt.Errorf("server is not listening")
	}

	var wg sync.WaitGroup

	defer wg.Wait()

	for {
		conn, err := listener.Accept()
		if err != nil {
			return nil
		}

		wg.Go(func() {
			s.handle(conn)
		})
	}
}

func (s *Server) handle(conn net.Conn) {
	defer func() {
		_ = conn.Close()
	}()

	now := time.Now()

	if s.Timeout != 0 {
		conn.SetDeadline(now.Add(s.Timeout))
	}

	if s.ReadTimeout != 0 {
		conn.SetReadDeadline(now.Add(s.ReadTimeout))
	}

	if s.WriteTimeout != 0 {
		conn.SetWriteDeadline(now.Add(s.WriteTimeout))
	}

	data, err := bufio.NewReader(io.LimitReader(conn, 1024+1+1)).ReadBytes('\n')
	if err != nil {
		if errors.Is(err, io.EOF) {
			writeHeader(conn, StatusBadRequest, "Request is too long")
		} else {
			writeHeader(conn, StatusTemporaryFailure, "Unable to read")
		}
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

	if parsed.Path != "" && !strings.HasPrefix(parsed.Path, "/") {
		writeHeader(conn, StatusBadRequest, "The URL path is relative")
		return
	}

	if parsed.User != nil {
		writeHeader(conn, StatusBadRequest, "The URL has user info")
		return
	}

	tlsConn, ok := conn.(*tls.Conn)
	if !ok {
		return
	}

	if err := tlsConn.Handshake(); err != nil {
		return
	}

	var cert *x509.Certificate

	if certs := tlsConn.ConnectionState().PeerCertificates; len(certs) > 0 {
		cert = certs[0]
	}

	if cert != nil {
		if now.Before(cert.NotBefore) {
			writeHeader(conn, StatusCerttificateNotValid, "Certificate not yet valid")
			return
		}

		if cert.NotAfter.Before(now) {
			writeHeader(conn, StatusCerttificateNotValid, "Certificate expired")
			return
		}

		if err := cert.CheckSignature(cert.SignatureAlgorithm, cert.RawTBSCertificate, cert.Signature); err != nil {
			writeHeader(conn, StatusCerttificateNotValid, "Invalid signature")
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
		Host:   parsed.Hostname(),
		Port:   port,
		Path:   cleanPath(parsed.Path),
		Query:  parsed.RawQuery,
		Cert:   cert,
	}

	responseWriter := responseWriter{
		w: conn,
	}

	s.Handler.Handle(&request, &responseWriter)

	if !responseWriter.header {
		responseWriter.writeDefaultHeader()
	}
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
		switch statusCode {
		case StatusSuccess:
			rw.validateMediaType(meta)
		case StatusTemporaryRedirection:
			rw.validateURL(meta)
		case StatusPermanentRedirection:
			rw.validateURL(meta)
		}
	}
}

func (rw *responseWriter) validateMediaType(s string) {
	if _, _, err := mime.ParseMediaType(s); err != nil {
		panic("invalid media type")
	}
}

func (rw *responseWriter) validateURL(s string) {
	if u, err := url.Parse(s); err != nil {
		panic("invalid URL")
	} else if !strings.HasPrefix(u.Path, "/") {
		panic("invalid URL path")
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
