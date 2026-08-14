package gemini

import (
	"bytes"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestRecorder(t *testing.T) {
	var r ResponseRecorder

	r.WriteHeader(StatusSuccess, "text/gemini")
	r.Write(bytes.Repeat([]byte{'x'}, 10))

	require.Equal(t, StatusSuccess, r.StatusCode)
	require.Equal(t, "text/gemini", r.Meta)
	require.Equal(t, 10, r.Written)
}

type mockResponseWriter struct {
	writeHeader func(statusCode StatusCode, meta string)
	write       func(p []byte) (int, error)
}

func (w mockResponseWriter) WriteHeader(statusCode StatusCode, meta string) {
	w.writeHeader(statusCode, meta)
}

func (w mockResponseWriter) Write(p []byte) (int, error) {
	return w.write(p)
}

func TestRecorderWrapped(t *testing.T) {
	w := mockResponseWriter{
		writeHeader: func(statusCode StatusCode, meta string) {
			require.Equal(t, StatusSuccess, statusCode)
			require.Equal(t, "text/gemini", meta)
		},
		write: func(p []byte) (int, error) {
			require.Len(t, p, 10)
			return 5, nil
		},
	}

	r := ResponseRecorder{
		Wrapped: w,
	}

	r.WriteHeader(StatusSuccess, "text/gemini")

	n, err := r.Write(bytes.Repeat([]byte{'x'}, 10))
	require.NoError(t, err)
	require.Equal(t, 5, n)
}
