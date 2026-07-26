package gemini

import (
	"context"
	"io"
	"time"
)

type deadlineAwareReadWriteCloser interface {
	io.ReadWriteCloser
	SetDeadline(t time.Time) error
	SetReadDeadline(t time.Time) error
	SetWriteDeadline(t time.Time) error
}

type timeoutReadWriteCloser struct {
	timeout      time.Duration
	readTimeout  time.Duration
	writeTimeout time.Duration
	rwc          deadlineAwareReadWriteCloser
}

func (rwc timeoutReadWriteCloser) Read(p []byte) (int, error) {
	now := time.Now()

	if rwc.timeout > 0 {
		if err := rwc.rwc.SetDeadline(now.Add(rwc.timeout)); err != nil {
			return 0, err
		}
	}

	if rwc.readTimeout > 0 {
		if err := rwc.rwc.SetReadDeadline(now.Add(rwc.readTimeout)); err != nil {
			return 0, err
		}
	}

	return rwc.rwc.Read(p)
}

func (rwc timeoutReadWriteCloser) Write(p []byte) (int, error) {
	now := time.Now()

	if rwc.timeout > 0 {
		if err := rwc.rwc.SetDeadline(now.Add(rwc.timeout)); err != nil {
			return 0, err
		}
	}

	if rwc.writeTimeout > 0 {
		if err := rwc.rwc.SetWriteDeadline(now.Add(rwc.writeTimeout)); err != nil {
			return 0, err
		}
	}

	return rwc.rwc.Write(p)
}

func (rwc timeoutReadWriteCloser) Close() error {
	now := time.Now()

	if rwc.timeout > 0 {
		if err := rwc.rwc.SetDeadline(now.Add(rwc.timeout)); err != nil {
			return err
		}
	}

	if rwc.readTimeout > 0 {
		if err := rwc.rwc.SetReadDeadline(now.Add(rwc.readTimeout)); err != nil {
			return err
		}
	}

	if rwc.writeTimeout > 0 {
		if err := rwc.rwc.SetWriteDeadline(now.Add(rwc.writeTimeout)); err != nil {
			return err
		}
	}

	return rwc.rwc.Close()
}

type contextAwareReadWriteCloser struct {
	ctx context.Context
	rwc io.ReadWriteCloser
}

func (rwc contextAwareReadWriteCloser) Read(p []byte) (int, error) {
	type result struct {
		n   int
		err error
	}

	ch := make(chan result, 1)

	go func() {
		n, err := rwc.rwc.Read(p)
		ch <- result{n, err}
	}()

	select {
	case result := <-ch:
		return result.n, result.err
	case <-rwc.ctx.Done():
		return 0, rwc.ctx.Err()
	}
}

func (rwc contextAwareReadWriteCloser) Write(p []byte) (int, error) {
	type result struct {
		n   int
		err error
	}

	ch := make(chan result, 1)

	go func() {
		n, err := rwc.rwc.Write(p)
		ch <- result{n, err}
	}()

	select {
	case result := <-ch:
		return result.n, result.err
	case <-rwc.ctx.Done():
		return 0, rwc.ctx.Err()
	}
}

func (rwc contextAwareReadWriteCloser) Close() error {
	ch := make(chan error, 1)

	go func() {
		ch <- rwc.rwc.Close()
	}()

	select {
	case err := <-ch:
		return err
	case <-rwc.ctx.Done():
		return rwc.ctx.Err()
	}
}
