package gemini

import (
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
