package gemini

import (
	"context"
	"maps"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
)

type valuesKey struct{}

// Values returns the path values indexed by their placeholders, if any. If the
// current path does not define any placeholder, Values returns nil.
func Values(ctx context.Context) map[string]string {
	if values, ok := ctx.Value(valuesKey{}).(map[string]string); ok {
		return maps.Clone(values)
	}

	return nil
}

// A Middleware wraps a handler and implements cross-cutting concerns.
type Middleware func(Handler) Handler

// Mux is a [Handler] that delegates to other registered handlers based on the
// requested path. If none of the registered handlers matches the request path,
// the mux responds with [StatusNotFound].
//
// A mux must be fully initialized before it's used. After serving the first
// request, the Mux is considered frozen and it will panic if a caller tries to
// change its configuration. Configuring a mux is not concurrency-safe.
type Mux struct {
	root         string
	parent       *Mux
	handlers     node[Handler]
	middlewares  []Middleware
	notFound     Handler
	notFoundOnce sync.Once
	frozen       atomic.Bool
}

// On registers a [Handler] for the provided path. The path can contain
// placeholders like `{foo}` that will be resolved against the corresponding
// component of the request path. The handler can retrieve the values of the
// placeholder using [Values].
//
// Matching a request path is a single linear pass over its components, with no
// backtracking. At each component, a literal match takes precedence over a
// placeholder, and a placeholder takes precedence over a wildcard, but this
// choice is final: if it doesn't lead to a registered handler by the end of
// the path, the request is not matched, even if a different choice at an
// earlier component would have led to one. For example, if both
// `/users/{uid}` and `/users/1/edit` are registered, a request to `/users/1`
// is not matched, because the literal component `1` takes precedence over the
// placeholder `{uid}` and does not itself lead to a registered handler. It's
// the caller's responsibility to register paths that don't rely on
// backtracking to be matched correctly.
//
// If the registered path ends with a slash (`/`), the handler is invoked for
// the registered path itself, but not for the same path without the trailing
// slash. For example, a handler registered for `/foo/` is called for requests
// to `/foo/`, but not for `/foo`.
//
// If a path ends with a wildcard (`*`) as its last component, the path matches
// any request path that starts with the prefix preceding the wildcard and has
// at least one more path component after it. The prefix itself, with or without
// a trailing slash, is not matched by the wildcard.  For example, a handler
// registered for `/foo/*` is called for requests to `/foo/bar` and
// `/foo/bar/baz`, but not for `/foo` or `/foo/`. When multiple paths ending
// with a wildcard are registered, if a request could not be matched exactly to
// a handler, the request is matched to the longest matching,
// wildcard-terminated path. For example, assume that `/*` and `/foo/*` are
// registered. A request to `/foo/bar` is matched by the handler registered at
// `/foo/*`, but a request to `/bar` is matched by the handler registered at
// `/*`.
//
// On panics if the mux is frozen, if the path is not absolute, if the handler
// is nil, if the path was already registered, or if registering the path
// would otherwise result in an inconsistent configuration for this mux.
func (m *Mux) On(path string, h Handler) {
	m.checkFrozen()
	m.checkPath(path)
	m.checkHandler(h)
	m.insert(m.composePath(path), m.applyMiddlewareLazily(h))
}

// Use registers a middleware for every [Handler] registered on this mux. The
// order of registration is respected. If middleware A is registered before
// middleware B, then A is invoked before B when processing a request, and both
// A and B are invoked before each handler.
//
// Use panics if the mux is frozen, or if the middleware is nil.
func (m *Mux) Use(middleware Middleware) {
	m.checkFrozen()
	m.checkMiddleware(middleware)
	m.middlewares = append(m.middlewares, middleware)
}

// Sub creates a sub-mux based on this mux and configures the sub-mux by calling
// the configure function.
//
// A sub-mux allows grouping together routes with a common path prefix. If a
// sub-mux is created at `/foo`, registering `/` in the sub-mux is equivalent to
// registering `/foo/` in the parent mux. Similarly, registering `/bar` in the
// sub-mux is equivalent to registering `/foo/bar` in the parent mux.
//
// The middleware registered in the sub-mux applies only to the routes registered
// in that sub-mux. The middleware registered in a parent mux applies to every
// handler in every sub-mux created (directly or transitively) from that parent
// mux. Sub-muxes can be arbitrarily nested. The middleware registered in a
// parent mux runs before the middleware registered in a sub-mux.
//
// Sub-muxes must not be used to serve requests. A sub-mux panics if it's asked
// to serve a request.
//
// Sub panics if the mux is frozen, or if the path is not absolute.
func (m *Mux) Sub(path string, configure func(m *Mux)) {
	m.checkFrozen()
	m.checkPath(path)
	sub := m.newSubRouter(path)
	configure(sub)
}

// Handle implements [Handler].
//
// As soon as the first request is served, this enters in a frozen state.
// Changing the configuration of the mux from this point onward will panic.
func (m *Mux) Handle(ctx context.Context, w ResponseWriter, r *Request) {
	m.frozen.Store(true)

	if m.parent != nil {
		panic("serving requests from a child mux")
	}

	handler, values := m.handlers.find(r.Path)

	if handler == nil {
		handler = m.newNotFoundHandler()
	}

	handler.Handle(m.contextWithValues(ctx, values), w, r)
}

func (m *Mux) composePath(path string) string {
	result := path

	for i := m; i != nil; i = i.parent {
		result = strings.TrimSuffix(i.root, "/") + "/" + strings.TrimPrefix(result, "/")
	}

	return result
}

func (m *Mux) insert(path string, h Handler) {
	for i := m; i != nil; i = i.parent {
		if i.parent == nil {
			i.handlers.insert(path, h)
		}
	}
}

func (m *Mux) newNotFoundHandler() Handler {
	m.notFoundOnce.Do(func() {
		m.notFound = m.applyMiddleware(HandlerFunc(func(ctx context.Context, w ResponseWriter, r *Request) {
			w.WriteHeader(StatusNotFound, "")
		}))
	})

	return m.notFound
}

func (m *Mux) applyMiddlewareLazily(h Handler) Handler {
	applyMiddleware := sync.OnceValue(func() Handler {
		return m.applyMiddleware(h)
	})

	return HandlerFunc(func(ctx context.Context, w ResponseWriter, request *Request) {
		applyMiddleware().Handle(ctx, w, request)
	})
}

func (m *Mux) applyMiddleware(h Handler) Handler {
	for i := m; i != nil; i = i.parent {
		for _, m := range slices.Backward(i.middlewares) {
			h = m(h)
		}
	}

	return h
}

func (m *Mux) checkFrozen() {
	for i := m; i != nil; i = i.parent {
		if i.frozen.Load() {
			m.frozen.Store(true)
			panic("the mux is frozen")
		}
	}
}

func (m *Mux) checkPath(p string) {
	if len(p) == 0 {
		panic("path must not be empty")
	}

	if p[0] != '/' {
		panic("path must be absolute")
	}
}

func (m *Mux) checkHandler(h Handler) {
	if h == nil {
		panic("handler must not be nil")
	}
}

func (m *Mux) checkMiddleware(middleware Middleware) {
	if middleware == nil {
		panic("middleware must not be nil")
	}
}

func (m *Mux) newSubRouter(path string) *Mux {
	return &Mux{
		root:   strings.TrimSuffix(path, "/"),
		parent: m,
	}
}

func (m *Mux) contextWithValues(ctx context.Context, values map[string]string) context.Context {
	if len(values) == 0 {
		return ctx
	}

	return context.WithValue(ctx, valuesKey{}, values)
}

type node[T any] struct {
	children         map[string]*node[T]
	placeholder      string
	placeholderChild *node[T]
	slashChild       *node[T]
	wildcardChild    *node[T]
	hasValue         bool
	value            T
}

func (n *node[T]) insert(path string, value T) {
	if path == "/" {
		if n.hasValue {
			panic("path already registered")
		}

		n.value = value
		n.hasValue = true
		return
	}

	curr := n
	fail := ""

	for c := range strings.SplitSeq(strings.Trim(path, "/"), "/") {
		if fail != "" {
			panic(fail)
		}

		if c == "*" {
			if curr.placeholderChild != nil {
				panic("wildcard must not overlap with placeholder")
			}

			next := new(node[T])
			curr.wildcardChild = next
			curr = next

			fail = "wildcard must be the last path component"

			continue
		}

		if strings.HasPrefix(c, "{") {
			if !strings.HasSuffix(c, "}") {
				panic("placeholders must be closed")
			}

			if len(c) < 3 {
				panic("placeholders must have a name")
			}

			if curr.wildcardChild != nil {
				panic("placeholder must not overlap with wildcard")
			}

			placeholder := c[1 : len(c)-1]

			if curr.placeholder == "" {
				next := new(node[T])
				curr.placeholder = placeholder
				curr.placeholderChild = next
				curr = next
				continue
			}

			if curr.placeholder != placeholder {
				panic("placeholders in the same position must be equal")
			}

			curr = curr.placeholderChild
			continue
		}

		if curr.children == nil {
			curr.children = make(map[string]*node[T])
		}

		next := curr.children[c]

		if next == nil {
			next = new(node[T])
			curr.children[c] = next
		}

		curr = next
	}

	if path[len(path)-1] == '/' {
		if path[len(path)-2] == '*' {
			panic("wildcards can't be followed by a slash")
		}

		if curr.slashChild == nil {
			curr.slashChild = new(node[T])
		}

		curr = curr.slashChild
	}

	if curr.hasValue {
		panic("path already registered")
	}

	curr.value = value
	curr.hasValue = true
}

func (n *node[T]) find(path string) (T, map[string]string) {
	if path == "/" {
		return n.value, nil
	}

	curr := n

	var (
		zero                 T
		wildcard             *node[T]
		wildcardPlaceholders map[string]string
		placeholders         map[string]string
	)

	for c := range strings.SplitSeq(strings.Trim(path, "/"), "/") {
		if curr.wildcardChild != nil {
			wildcard = curr.wildcardChild
			wildcardPlaceholders = maps.Clone(placeholders)
		}

		if curr.children != nil {
			next := curr.children[c]

			if next != nil {
				curr = next
				continue
			}
		}

		if curr.placeholder != "" {
			if placeholders == nil {
				placeholders = make(map[string]string)
			}
			placeholders[curr.placeholder] = c
			curr = curr.placeholderChild
			continue
		}

		if wildcard != nil && wildcard.hasValue {
			return wildcard.value, wildcardPlaceholders
		}

		return zero, nil
	}

	if strings.HasSuffix(path, "/") {
		curr = curr.slashChild
	}

	if curr != nil && curr.hasValue {
		return curr.value, placeholders
	}

	if wildcard != nil && wildcard.hasValue {
		return wildcard.value, wildcardPlaceholders
	}

	return zero, nil
}
