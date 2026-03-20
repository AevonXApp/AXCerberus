// Package pipeline provides a composable HTTP middleware chain.
package pipeline

import "net/http"

// Middleware is a function that wraps an http.Handler with additional behavior.
type Middleware func(http.Handler) http.Handler

// Chain composes multiple middleware left-to-right: the first middleware
// in the list is the outermost wrapper (runs first on request, last on response).
//
//	chain := Chain(logging, rateLimit, waf)
//	handler := chain(upstream)
//	// request flow: logging → rateLimit → waf → upstream
func Chain(mws ...Middleware) Middleware {
	return func(final http.Handler) http.Handler {
		for i := len(mws) - 1; i >= 0; i-- {
			final = mws[i](final)
		}
		return final
	}
}
