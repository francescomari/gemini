package gemini

// ResponseRecorder records the status code, meta, and amount of bytes written
// by a handler. Optionally, a ResponseRecorder can wrap a ResponseWriter. When
// wrapping a ResponseWriter, calls to the WriteHeader and Write are dispatched
// to the wrapped ResponseWriter.
type ResponseRecorder struct {
	Wrapped    ResponseWriter
	StatusCode StatusCode
	Meta       string
	Written    int
}

// WriteHeader implements ResponseWriter.
func (r *ResponseRecorder) WriteHeader(statusCode StatusCode, meta string) {
	r.StatusCode = statusCode
	r.Meta = meta

	if r.Wrapped != nil {
		r.Wrapped.WriteHeader(statusCode, meta)
	}
}

// Write implements ResponseWriter.
func (r *ResponseRecorder) Write(p []byte) (int, error) {
	r.Written += len(p)

	if r.Wrapped != nil {
		return r.Wrapped.Write(p)
	}

	return len(p), nil
}
