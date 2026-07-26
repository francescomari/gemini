package gemini

import (
	"context"
	"errors"
	"io"
	"testing"
	"testing/synctest"
	"time"
)

type mockReadWriteCloser struct {
	read  func(p []byte) (int, error)
	write func(p []byte) (int, error)
	close func() error
}

func (rwc mockReadWriteCloser) Read(p []byte) (int, error) {
	return rwc.read(p)
}

func (rwc mockReadWriteCloser) Write(p []byte) (int, error) {
	return rwc.write(p)
}

func (rwc mockReadWriteCloser) Close() error {
	return rwc.close()
}

type mockDeadlineAwareReadWriteCloser struct {
	event int

	deadline      time.Time
	deadlineSetAt int
	deadlineErr   error

	readDeadline      time.Time
	readDeadlineSetAt int
	readDeadlineErr   error

	writeDeadline      time.Time
	writeDeadlineSetAt int
	writeDeadlineErr   error
}

func (rwc *mockDeadlineAwareReadWriteCloser) Read(p []byte) (int, error) {
	return 0, nil
}

func (rwc *mockDeadlineAwareReadWriteCloser) Write(p []byte) (int, error) {
	return 0, nil
}

func (rwc *mockDeadlineAwareReadWriteCloser) Close() error {
	return nil
}

func (rwc *mockDeadlineAwareReadWriteCloser) SetDeadline(deadline time.Time) error {
	rwc.deadline = deadline
	rwc.deadlineSetAt = rwc.nextEvent()
	return rwc.deadlineErr
}

func (rwc *mockDeadlineAwareReadWriteCloser) SetReadDeadline(deadline time.Time) error {
	rwc.readDeadline = deadline
	rwc.readDeadlineSetAt = rwc.nextEvent()
	return rwc.readDeadlineErr
}

func (rwc *mockDeadlineAwareReadWriteCloser) SetWriteDeadline(deadline time.Time) error {
	rwc.writeDeadline = deadline
	rwc.writeDeadlineSetAt = rwc.nextEvent()
	return rwc.writeDeadlineErr
}

func (rwc *mockDeadlineAwareReadWriteCloser) nextEvent() int {
	e := rwc.event
	rwc.event += 1
	return e
}

func TestTimeoutReadWriteCloser(t *testing.T) {
	t.Run("timeout", func(t *testing.T) {
		synctest.Test(t, func(t *testing.T) {
			m := mockDeadlineAwareReadWriteCloser{}

			rwc := timeoutReadWriteCloser{
				timeout: time.Second,
				rwc:     &m,
			}

			rwc.Read(nil)

			if !time.Now().Add(time.Second).Equal(m.deadline) {
				t.Fatalf("deadline not set for read")
			}
			if !m.readDeadline.IsZero() {
				t.Fatalf("read deadline set for read")
			}

			time.Sleep(time.Second)
			rwc.Write(nil)

			if !time.Now().Add(time.Second).Equal(m.deadline) {
				t.Fatalf("deadline not set for write")
			}
			if !m.writeDeadline.IsZero() {
				t.Fatalf("write deadline set for write")
			}

			time.Sleep(time.Second)
			rwc.Close()

			if !time.Now().Add(time.Second).Equal(m.deadline) {
				t.Fatalf("deadline not set for close")
			}
			if !m.readDeadline.IsZero() {
				t.Fatalf("read deadline set for read")
			}
			if !m.writeDeadline.IsZero() {
				t.Fatalf("write deadline set for write")
			}
		})
	})

	t.Run("read timeout", func(t *testing.T) {
		synctest.Test(t, func(t *testing.T) {
			m := mockDeadlineAwareReadWriteCloser{}

			rwc := timeoutReadWriteCloser{
				readTimeout: time.Second,
				rwc:         &m,
			}

			rwc.Read(nil)

			if !m.deadline.IsZero() {
				t.Fatalf("deadline set for read")
			}
			if !time.Now().Add(time.Second).Equal(m.readDeadline) {
				t.Fatalf("read deadline not set for read")
			}

			time.Sleep(time.Second)
			rwc.Write(nil)

			if !m.deadline.IsZero() {
				t.Fatalf("deadline set for write")
			}
			if !m.writeDeadline.IsZero() {
				t.Fatalf("write deadline set for write")
			}

			time.Sleep(time.Second)
			rwc.Close()

			if !m.deadline.IsZero() {
				t.Fatalf("deadline set for close")
			}
			if !time.Now().Add(time.Second).Equal(m.readDeadline) {
				t.Fatalf("read deadline not set for close")
			}
			if !m.writeDeadline.IsZero() {
				t.Fatalf("write deadline set for close")
			}
		})
	})

	t.Run("write timeout", func(t *testing.T) {
		synctest.Test(t, func(t *testing.T) {
			m := mockDeadlineAwareReadWriteCloser{}

			rwc := timeoutReadWriteCloser{
				writeTimeout: time.Second,
				rwc:          &m,
			}

			rwc.Read(nil)

			if !m.deadline.IsZero() {
				t.Fatalf("deadline set for read")
			}
			if !m.readDeadline.IsZero() {
				t.Fatalf("read deadline set for read")
			}

			time.Sleep(time.Second)
			rwc.Write(nil)

			if !m.deadline.IsZero() {
				t.Fatalf("deadline set for write")
			}
			if !time.Now().Add(time.Second).Equal(m.writeDeadline) {
				t.Fatalf("write deadline not set for write")
			}

			time.Sleep(time.Second)
			rwc.Close()

			if !m.deadline.IsZero() {
				t.Fatalf("deadline set for close")
			}
			if !m.readDeadline.IsZero() {
				t.Fatalf("read deadline set for close")
			}
			if !time.Now().Add(time.Second).Equal(m.writeDeadline) {
				t.Fatalf("write deadline not set for close")
			}
		})
	})

	t.Run("timeout error", func(t *testing.T) {
		e := errors.New("set deadline")

		m := mockDeadlineAwareReadWriteCloser{
			deadlineErr: e,
		}

		rwc := timeoutReadWriteCloser{
			timeout: time.Second,
			rwc:     &m,
		}

		if _, err := rwc.Read(nil); err != e {
			t.Fatalf("unexpected error from read: %v", err)
		}
		if _, err := rwc.Write(nil); err != e {
			t.Fatalf("unexpcted error from write: %v", err)
		}
		if err := rwc.Close(); err != e {
			t.Fatalf("unexpcted error from close: %v", err)
		}
	})

	t.Run("read timeout error", func(t *testing.T) {
		e := errors.New("set read deadline")

		m := mockDeadlineAwareReadWriteCloser{
			readDeadlineErr: e,
		}

		rwc := timeoutReadWriteCloser{
			readTimeout: time.Second,
			rwc:         &m,
		}

		if _, err := rwc.Read(nil); err != e {
			t.Fatalf("unexpected error from read: %v", err)
		}
		if _, err := rwc.Write(nil); err != nil {
			t.Fatalf("unexpected error from write: %v", err)
		}
		if err := rwc.Close(); err != e {
			t.Fatalf("unexpected error from close: %v", err)
		}
	})

	t.Run("write timeout error", func(t *testing.T) {
		e := errors.New("set write deadline")

		m := mockDeadlineAwareReadWriteCloser{
			writeDeadlineErr: e,
		}

		rwc := timeoutReadWriteCloser{
			writeTimeout: time.Second,
			rwc:          &m,
		}

		if _, err := rwc.Read(nil); err != nil {
			t.Fatalf("unexpected error from read: %v", err)
		}
		if _, err := rwc.Write(nil); err != e {
			t.Fatalf("unexpected error from write: %v", err)
		}
		if err := rwc.Close(); err != e {
			t.Fatalf("unexpected error from close: %v", err)
		}
	})

	t.Run("read timeout overrides timeout", func(t *testing.T) {
		m := mockDeadlineAwareReadWriteCloser{}

		rwc := timeoutReadWriteCloser{
			timeout:     time.Second,
			readTimeout: time.Second,
			rwc:         &m,
		}

		rwc.Read(nil)

		if m.deadlineSetAt > m.readDeadlineSetAt {
			t.Fatalf("deadline set after read deadline")
		}

		rwc.Close()

		if m.deadlineSetAt > m.readDeadlineSetAt {
			t.Fatalf("deadline set after read deadline")
		}
	})

	t.Run("write timeout overrides timeout", func(t *testing.T) {
		m := mockDeadlineAwareReadWriteCloser{}

		rwc := timeoutReadWriteCloser{
			timeout:      time.Second,
			writeTimeout: time.Second,
			rwc:          &m,
		}

		rwc.Read(nil)

		if m.deadlineSetAt > m.writeDeadlineSetAt {
			t.Fatalf("deadline set after write deadline")
		}

		rwc.Close()

		if m.deadlineSetAt > m.writeDeadlineSetAt {
			t.Fatalf("deadline set after write deadline")
		}
	})
}

func TestContextAwareReadWriteCloser(t *testing.T) {
	t.Run("fast read", func(t *testing.T) {
		synctest.Test(t, func(t *testing.T) {
			ctx, cancel := context.WithCancel(t.Context())
			defer cancel()

			m := mockReadWriteCloser{
				read: func(p []byte) (int, error) {
					return 0, io.EOF
				},
			}

			rwc := contextAwareReadWriteCloser{
				ctx: ctx,
				rwc: m,
			}

			if _, err := rwc.Read(nil); err != io.EOF {
				t.Fatalf("invalid error: %v", err)
			}

			synctest.Wait()
		})
	})

	t.Run("slow read", func(t *testing.T) {
		synctest.Test(t, func(t *testing.T) {
			ctx, cancel := context.WithCancel(t.Context())

			read := make(chan struct{})

			m := mockReadWriteCloser{
				read: func(p []byte) (int, error) {
					<-read
					return 0, io.EOF
				},
			}

			rwc := contextAwareReadWriteCloser{
				ctx: ctx,
				rwc: m,
			}

			go func() {
				if _, err := rwc.Read(nil); err != context.Canceled {
					t.Errorf("invalid error: %v", err)
				}
			}()

			synctest.Wait()

			cancel()
			synctest.Wait()

			close(read)
			synctest.Wait()
		})
	})

	t.Run("fast write", func(t *testing.T) {
		synctest.Test(t, func(t *testing.T) {
			ctx, cancel := context.WithCancel(t.Context())
			defer cancel()

			m := mockReadWriteCloser{
				write: func(p []byte) (int, error) {
					return 0, nil
				},
			}

			rwc := contextAwareReadWriteCloser{
				ctx: ctx,
				rwc: m,
			}

			if _, err := rwc.Write(nil); err != nil {
				t.Fatalf("write: %v", err)
			}

			synctest.Wait()
		})
	})

	t.Run("slow write", func(t *testing.T) {
		synctest.Test(t, func(t *testing.T) {
			ctx, cancel := context.WithCancel(t.Context())

			write := make(chan struct{})

			m := mockReadWriteCloser{
				write: func(p []byte) (int, error) {
					<-write
					return 0, nil
				},
			}

			rwc := contextAwareReadWriteCloser{
				ctx: ctx,
				rwc: m,
			}

			go func() {
				if _, err := rwc.Write(nil); err != context.Canceled {
					t.Errorf("invalid error: %v", err)
				}
			}()

			synctest.Wait()

			cancel()
			synctest.Wait()

			close(write)
			synctest.Wait()
		})
	})

	t.Run("fast close", func(t *testing.T) {
		synctest.Test(t, func(t *testing.T) {
			ctx, cancel := context.WithCancel(t.Context())
			defer cancel()

			m := mockReadWriteCloser{
				close: func() error {
					return nil
				},
			}

			rwc := contextAwareReadWriteCloser{
				ctx: ctx,
				rwc: m,
			}

			if err := rwc.Close(); err != nil {
				t.Fatalf("close: %v", err)
			}

			synctest.Wait()
		})
	})

	t.Run("slow close", func(t *testing.T) {
		synctest.Test(t, func(t *testing.T) {
			ctx, cancel := context.WithCancel(t.Context())

			quit := make(chan struct{})

			m := mockReadWriteCloser{
				close: func() error {
					<-quit
					return nil
				},
			}

			rwc := contextAwareReadWriteCloser{
				ctx: ctx,
				rwc: m,
			}

			go func() {
				if err := rwc.Close(); err != context.Canceled {
					t.Errorf("invalid error: %v", err)
				}
			}()

			synctest.Wait()

			cancel()
			synctest.Wait()

			close(quit)
			synctest.Wait()
		})
	})
}
