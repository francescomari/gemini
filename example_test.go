package gemini_test

import (
	"context"
	"crypto/tls"
	"fmt"
	"log/slog"
	"net"
	"os"
	"time"

	"github.com/francescomari/gemini"
)

func ExampleServer_run() {
	cert, err := tls.LoadX509KeyPair(os.Getenv("TLS_CERT"), os.Getenv("TLS_KEY"))
	if err != nil {
		panic(fmt.Sprintf("load X.509 key pair: %v", err))
	}

	listener, err := net.Listen("tcp", ":1965")
	if err != nil {
		panic(fmt.Sprintf("listen: %v", err))
	}

	handler := gemini.HandlerFunc(func(ctx context.Context, w gemini.ResponseWriter, r *gemini.Request) {
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

func ExampleServer_timeout() {
	cert, err := tls.LoadX509KeyPair(os.Getenv("TLS_CERT"), os.Getenv("TLS_KEY"))
	if err != nil {
		panic(fmt.Sprintf("load X.509 key pair: %v", err))
	}

	listener, err := net.Listen("tcp", ":1965")
	if err != nil {
		panic(fmt.Sprintf("listen: %v", err))
	}

	handler := gemini.HandlerFunc(func(ctx context.Context, w gemini.ResponseWriter, r *gemini.Request) {
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

func ExampleServer_readWriteTimeouts() {
	cert, err := tls.LoadX509KeyPair(os.Getenv("TLS_CERT"), os.Getenv("TLS_KEY"))
	if err != nil {
		panic(fmt.Sprintf("load X.509 key pair: %v", err))
	}

	listener, err := net.Listen("tcp", ":1965")
	if err != nil {
		panic(fmt.Sprintf("listen: %v", err))
	}

	handler := gemini.HandlerFunc(func(ctx context.Context, w gemini.ResponseWriter, r *gemini.Request) {
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

func ExampleMux() {
	var m gemini.Mux

	// Use a middleware to track the duration of each incoming request.

	m.Use(func(h gemini.Handler) gemini.Handler {
		return gemini.HandlerFunc(func(ctx context.Context, w gemini.ResponseWriter, r *gemini.Request) {
			start := time.Now()
			h.Handle(ctx, w, r)
			slog.Info("request complete", slog.String("path", r.Path), slog.Any("duration", time.Since(start)))
		})
	})

	// The root (/) is called for requests to the root of this mux, but it also
	// acts as a fallback when no other handler could be found. When registering a
	// root handler, remember to check the request path.

	m.On("/", gemini.HandlerFunc(func(ctx context.Context, w gemini.ResponseWriter, r *gemini.Request) {
		if r.Path == "/" {
			fmt.Fprint(w, "Index page\r\n")
		} else {
			w.WriteHeader(gemini.StatusNotFound, "")
		}
	}))

	// Use sub-muxes to group handlers sharing a common path prefix. Handlers can
	// be registered at parameterized paths.

	m.Sub("/users", func(m *gemini.Mux) {
		m.On("/", gemini.HandlerFunc(func(ctx context.Context, w gemini.ResponseWriter, r *gemini.Request) {
			// Show a list of users.
		}))
		m.On("/{id}", gemini.HandlerFunc(func(ctx context.Context, w gemini.ResponseWriter, r *gemini.Request) {
			values := gemini.Values(ctx)

			if values["id"] == "self" {
				// Show the authenticated user's profile.
			} else {
				// Show the profile of some other user.
			}
		}))
	})
}
