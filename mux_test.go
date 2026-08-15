package gemini

import (
	"context"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestNodeFind(t *testing.T) {
	var (
		n node[int]
		v int
	)

	v, _ = n.find("/")
	require.Equal(t, 0, v)
	v, _ = n.find("/foo")
	require.Equal(t, 0, v)

	n.insert("/", 1)

	v, _ = n.find("/")
	require.Equal(t, 1, v)
	v, _ = n.find("/foo")
	require.Equal(t, 0, v)

	n.insert("/foo", 2)

	v, _ = n.find("/")
	require.Equal(t, 1, v)
	v, _ = n.find("/foo")
	require.Equal(t, 2, v)
	v, _ = n.find("/bar")
	require.Equal(t, 0, v)

	n.insert("/bar/", 3)

	v, _ = n.find("/bar")
	require.Equal(t, 0, v)
	v, _ = n.find("/bar/")
	require.Equal(t, 3, v)
	v, _ = n.find("/bar/baz")
	require.Equal(t, 0, v)
	v, _ = n.find("/bar/baz/")
	require.Equal(t, 0, v)

	n.insert("/baz/*", 4)

	v, _ = n.find("/baz")
	require.Equal(t, 0, v)
	v, _ = n.find("/baz/")
	require.Equal(t, 0, v)
	v, _ = n.find("/baz/quz")
	require.Equal(t, 4, v)
}

func TestNodePlaceholders(t *testing.T) {
	var (
		n node[int]
		v int
		p map[string]string
	)

	n.insert("/users/{uid}", 1)
	n.insert("/users/{uid}/", 2)
	n.insert("/users/{uid}/profile", 3)

	v, p = n.find("/users/1")
	require.Equal(t, 1, v)
	require.Equal(t, "1", p["uid"])

	v, p = n.find("/users/1/")
	require.Equal(t, 2, v)
	require.Equal(t, "1", p["uid"])

	v, p = n.find("/users/1/posts")
	require.Equal(t, 0, v)

	v, p = n.find("/users/1/profile")
	require.Equal(t, 3, v)
	require.Equal(t, "1", p["uid"])

	n.insert("/a/{a}/b/*", 4)
	n.insert("/a/{a}/b/c/{c}/d", 5)

	v, p = n.find("/a/1/b/c")
	require.Equal(t, 4, v)
	require.Contains(t, p, "a")
	require.NotContains(t, p, "c")
}

func TestNodeRootWildcard(t *testing.T) {
	var (
		n node[int]
		v int
	)

	n.insert("/", 1)

	v, _ = n.find("/")
	require.Equal(t, 1, v)
	v, _ = n.find("/a")
	require.Equal(t, 0, v)

	n.insert("/*", 1)

	v, _ = n.find("/")
	require.Equal(t, 1, v)
	v, _ = n.find("/a")
	require.Equal(t, 1, v)
}

func TestWildcardSlashPanic(t *testing.T) {
	var n node[int]

	require.PanicsWithValue(t, "wildcards can't be followed by a slash", func() {
		n.insert("/*/", 1)
	})
}

func TestNoWildcardSuffixPanic(t *testing.T) {
	var n node[int]

	require.PanicsWithValue(t, "wildcard must be the last path component", func() {
		n.insert("/foo/*/bar", 1)
	})
}

func TestNodePlaceholderWildcardPanic(t *testing.T) {
	var n node[int]

	n.insert("/{x}", 1)

	require.PanicsWithValue(t, "wildcard must not overlap with placeholder", func() {
		n.insert("/*", 2)
	})
}

func TestNodeWildcardPlaceholderPanic(t *testing.T) {
	var n node[int]

	n.insert("/*", 1)

	require.PanicsWithValue(t, "placeholder must not overlap with wildcard", func() {
		n.insert("/{x}", 2)
	})
}

func TestNodePlaceholderNotClosed(t *testing.T) {
	var n node[int]

	require.PanicsWithValue(t, "placeholders must be closed", func() {
		n.insert("/{unclosed", 1)
	})
}

func TestNodeEmptyPlaceholder(t *testing.T) {
	var n node[int]

	require.PanicsWithValue(t, "placeholders must have a name", func() {
		n.insert("/{}", 1)
	})
}

func TestMultipleDifferentPlaceholders(t *testing.T) {
	var n node[int]

	n.insert("/{foo}", 1)
	n.insert("/{foo}", 2)

	v, p := n.find("/something")
	require.Equal(t, 2, v)
	require.Equal(t, map[string]string{"foo": "something"}, p)

	require.PanicsWithValue(t, "placeholders in the same position must be equal", func() {
		n.insert("/{bar}", 3)
	})
}

func TestMuxEmptyPath(t *testing.T) {
	var m Mux

	require.PanicsWithValue(t, "path must not be empty", func() {
		m.On("", nil)
	})
}

func TestMuxRelativePath(t *testing.T) {
	var m Mux

	require.PanicsWithValue(t, "path must be absolute", func() {
		m.On("relative/path", nil)
	})
}

func TestMuxNilHandler(t *testing.T) {
	var m Mux

	require.PanicsWithValue(t, "handler must not be nil", func() {
		m.On("/", nil)
	})
}

func TestMuxNilMiddleware(t *testing.T) {
	var m Mux

	require.PanicsWithValue(t, "middleware must not be nil", func() {
		m.Use(nil)
	})
}

func TestMuxFrozen(t *testing.T) {
	var m Mux

	m.On("/", HandlerFunc(func(ctx context.Context, w ResponseWriter, r *Request) {}))

	r := Request{
		Path: "/",
	}

	m.Handle(t.Context(), nil, &r)

	require.PanicsWithValue(t, "the mux is frozen", func() {
		m.On("/foo", HandlerFunc(func(ctx context.Context, w ResponseWriter, r *Request) {}))
	})

	require.PanicsWithValue(t, "the mux is frozen", func() {
		m.Use(func(h Handler) Handler { return h })
	})

	require.PanicsWithValue(t, "the mux is frozen", func() {
		m.Sub("/foo", func(m *Mux) {})
	})
}

func TestSubMuxFrozen(t *testing.T) {
	var m Mux

	m.On("/", HandlerFunc(func(ctx context.Context, w ResponseWriter, r *Request) {}))

	var child *Mux

	m.Sub("/foo", func(m *Mux) {
		m.On("/", HandlerFunc(func(ctx context.Context, w ResponseWriter, r *Request) {}))
		child = m
	})

	r := Request{
		Path: "/",
	}

	m.Handle(t.Context(), nil, &r)

	require.PanicsWithValue(t, "the mux is frozen", func() {
		child.On("/foo", HandlerFunc(func(ctx context.Context, w ResponseWriter, r *Request) {}))
	})

	require.PanicsWithValue(t, "the mux is frozen", func() {
		child.Use(func(h Handler) Handler { return h })
	})

	require.PanicsWithValue(t, "the mux is frozen", func() {
		child.Sub("/foo", func(m *Mux) {})
	})
}

func TestMuxExact(t *testing.T) {
	var m Mux

	called := false

	m.On("/foo", HandlerFunc(func(ctx context.Context, w ResponseWriter, r *Request) {
		called = true
	}))

	r := Request{
		Path: "/foo",
	}

	m.Handle(t.Context(), nil, &r)

	require.True(t, called)
}

func TestSubMuxPanic(t *testing.T) {
	var m Mux

	var child *Mux

	m.Sub("/foo", func(m *Mux) {
		m.On("/bar", HandlerFunc(func(ctx context.Context, w ResponseWriter, r *Request) {
			// Do nothing.
		}))

		child = m
	})

	require.PanicsWithValue(t, "serving requests from a child mux", func() {
		child.Handle(t.Context(), nil, nil)
	})
}

func TestSubMuxRoot(t *testing.T) {
	var m Mux

	parent := false

	m.On("/foo", HandlerFunc(func(ctx context.Context, w ResponseWriter, r *Request) {
		parent = true
	}))

	child := false

	m.Sub("/foo", func(r *Mux) {
		r.On("/", HandlerFunc(func(ctx context.Context, w ResponseWriter, r *Request) {
			child = true
		}))
	})

	r := Request{
		Path: "/foo/",
	}

	m.Handle(t.Context(), nil, &r)

	require.False(t, parent)
	require.True(t, child)
}

func TestSubMuxPath(t *testing.T) {
	var m Mux

	called := false

	m.Sub("/foo", func(r *Mux) {
		r.On("/bar", HandlerFunc(func(ctx context.Context, w ResponseWriter, r *Request) {
			called = true
		}))
	})

	r := Request{
		Path: "/foo/bar",
	}

	m.Handle(t.Context(), nil, &r)

	require.True(t, called)
}

func TestMuxNoValues(t *testing.T) {
	var m Mux

	m.On("/", HandlerFunc(func(ctx context.Context, w ResponseWriter, r *Request) {
		require.Nil(t, Values(ctx))
	}))

	r := Request{
		Path: "/",
	}

	m.Handle(t.Context(), nil, &r)
}

func TestMuxValues(t *testing.T) {
	var m Mux

	m.On("/groups/{gid}/users/{uid}", HandlerFunc(func(ctx context.Context, w ResponseWriter, r *Request) {
		expected := map[string]string{"gid": "1", "uid": "2"}
		require.Equal(t, expected, Values(ctx))
	}))

	r := Request{
		Path: "/groups/1/users/2",
	}

	m.Handle(t.Context(), nil, &r)
}

func TestSubMuxValues(t *testing.T) {
	var m Mux

	m.Sub("/groups/{gid}", func(r *Mux) {
		r.On("/users/{uid}", HandlerFunc(func(ctx context.Context, w ResponseWriter, r *Request) {
			expected := map[string]string{"gid": "1", "uid": "2"}
			require.Equal(t, expected, Values(ctx))
		}))
	})

	r := Request{
		Path: "/groups/1/users/2",
	}

	m.Handle(t.Context(), nil, &r)
}

func TestSubMuxValueOverride(t *testing.T) {
	var m Mux

	m.Sub("/groups/{id}", func(r *Mux) {
		r.On("/users/{id}", HandlerFunc(func(ctx context.Context, w ResponseWriter, r *Request) {
			expected := map[string]string{"id": "2"}
			require.Equal(t, expected, Values(ctx))
		}))
	})

	r := Request{
		Path: "/groups/1/users/2",
	}

	m.Handle(t.Context(), nil, &r)
}

func TestMiddleware(t *testing.T) {
	var m Mux

	var sequence []string

	m.Use(func(h Handler) Handler {
		return HandlerFunc(func(ctx context.Context, w ResponseWriter, r *Request) {
			sequence = append(sequence, "first - before")
			h.Handle(ctx, w, r)
			sequence = append(sequence, "first - after")
		})
	})

	m.Use(func(h Handler) Handler {
		return HandlerFunc(func(ctx context.Context, w ResponseWriter, r *Request) {
			sequence = append(sequence, "second - before")
			h.Handle(ctx, w, r)
			sequence = append(sequence, "second - after")
		})
	})

	m.On("/", HandlerFunc(func(ctx context.Context, w ResponseWriter, r *Request) {
		sequence = append(sequence, "handler")
	}))

	r := Request{
		Path: "/",
	}

	m.Handle(t.Context(), nil, &r)

	expected := []string{
		"first - before",
		"second - before",
		"handler",
		"second - after",
		"first - after",
	}

	require.Equal(t, expected, sequence)
}

func TestSubMuxMiddleware(t *testing.T) {
	var m Mux

	var sequence []string

	m.Use(func(h Handler) Handler {
		return HandlerFunc(func(ctx context.Context, w ResponseWriter, r *Request) {
			sequence = append(sequence, "outer - before")
			h.Handle(ctx, w, r)
			sequence = append(sequence, "outer - after")
		})
	})

	m.Sub("/foo", func(r *Mux) {
		r.Use(func(h Handler) Handler {
			return HandlerFunc(func(ctx context.Context, w ResponseWriter, r *Request) {
				sequence = append(sequence, "inner - before")
				h.Handle(ctx, w, r)
				sequence = append(sequence, "inner - after")
			})
		})

		r.On("/bar", HandlerFunc(func(ctx context.Context, w ResponseWriter, r *Request) {
			sequence = append(sequence, "handler")
		}))
	})

	r := Request{
		Path: "/foo/bar",
	}

	m.Handle(t.Context(), nil, &r)

	expected := []string{
		"outer - before",
		"inner - before",
		"handler",
		"inner - after",
		"outer - after",
	}

	require.Equal(t, expected, sequence)
}

func TestNotFoundHandler(t *testing.T) {
	var m Mux

	called := false

	m.Use(func(h Handler) Handler {
		return HandlerFunc(func(ctx context.Context, w ResponseWriter, r *Request) {
			called = true
			h.Handle(ctx, w, r)
		})
	})

	r := Request{
		Path: "/does-not-exist",
	}

	var w ResponseRecorder

	m.Handle(t.Context(), &w, &r)

	require.True(t, called)
	require.Equal(t, StatusNotFound, w.StatusCode)
}
