package gemini_test

import (
	"crypto/tls"
	"fmt"
	"net"
	"os"
	"time"

	"github.com/francescomari/gemini"
)

func Example_run() {
	cert, err := tls.LoadX509KeyPair(os.Getenv("TLS_CERT"), os.Getenv("TLS_KEY"))
	if err != nil {
		panic(fmt.Sprintf("load X.509 key pair: %v", err))
	}

	listener, err := net.Listen("tcp", ":1965")
	if err != nil {
		panic(fmt.Sprintf("listen: %v", err))
	}

	handler := gemini.HandlerFunc(func(r *gemini.Request, w gemini.ResponseWriter) {
		fmt.Fprint(w, "=> https://github.com/francescomari/gemini Yet another Gemini server\r\n")
	})

	server := gemini.Server{
		Cert:    cert,
		Handler: handler,
	}

	if err := server.Serve(listener); err != nil {
		panic(fmt.Sprintf("serve: %v", err))
	}
}

func Example_timeout() {
	cert, err := tls.LoadX509KeyPair(os.Getenv("TLS_CERT"), os.Getenv("TLS_KEY"))
	if err != nil {
		panic(fmt.Sprintf("load X.509 key pair: %v", err))
	}

	listener, err := net.Listen("tcp", ":1965")
	if err != nil {
		panic(fmt.Sprintf("listen: %v", err))
	}

	handler := gemini.HandlerFunc(func(r *gemini.Request, w gemini.ResponseWriter) {
		fmt.Fprint(w, "=> https://github.com/francescomari/gemini Yet another Gemini server\r\n")
	})

	// Configure a single timeout for both read and write operations.

	server := gemini.Server{
		Cert:    cert,
		Handler: handler,
		Timeout: time.Second,
	}

	if err := server.Serve(listener); err != nil {
		panic(fmt.Sprintf("serve: %v", err))
	}
}

func Example_readWriteTimeouts() {
	cert, err := tls.LoadX509KeyPair(os.Getenv("TLS_CERT"), os.Getenv("TLS_KEY"))
	if err != nil {
		panic(fmt.Sprintf("load X.509 key pair: %v", err))
	}

	listener, err := net.Listen("tcp", ":1965")
	if err != nil {
		panic(fmt.Sprintf("listen: %v", err))
	}

	handler := gemini.HandlerFunc(func(r *gemini.Request, w gemini.ResponseWriter) {
		fmt.Fprint(w, "=> https://github.com/francescomari/gemini Yet another Gemini server\r\n")
	})

	// Configure separate timeouts for read and write operations.

	server := gemini.Server{
		Cert:         cert,
		Handler:      handler,
		ReadTimeout:  2 * time.Second,
		WriteTimeout: 3 * time.Second,
	}

	if err := server.Serve(listener); err != nil {
		panic(fmt.Sprintf("serve: %v", err))
	}
}
