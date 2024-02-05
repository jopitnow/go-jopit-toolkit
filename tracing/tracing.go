package tracing

import (
	"context"
	"net/http"
)

const (
	// RequestIDHeaderHTTP exposes the header to use for reading
	// and propagating the request id from an HTTP context.
	RequestIDHeaderHTTP = RequestIDHeader

	// RequestFlowStarterHeaderHTTP is the HTTP header that the tracing
	// library forwards when the application start a new request flow.
	RequestFlowStarterHeaderHTTP = RequestFlowStarterHeader

	// ForwardedHeadersNameHTTP is the HTTP header that contains the comma
	// separated value of request headers that must be forwarded to the
	// outgoing HTTP request that the application performs.
	ForwardedHeadersNameHTTP = ForwardedHeadersName
)

// ContextFromRequest given a http.Request returns a context decorated with the
// headers from the request that must be forwarded by the application in http
// requests to external services.
func ContextFromRequest(req *http.Request) context.Context {
	return ContextFromHeader(req.Context(), req.Header)
}

// ForwardedHeaders returns the headers that must be forwarded by HTTP clients
// given a request context.Context.
func ForwardedHeaders(ctx context.Context) http.Header {
	h := ForwardedHeadersUtil(ctx)
	out := make(http.Header, len(h))
	for k := range h {
		out.Add(k, h.Get(k))
	}
	return out
}

// RequestID returns the request id given a context.
// If the context does not contain a requestID, then
// an empty string is returned.
func RequestID(ctx context.Context) string {
	headers := ForwardedHeaders(ctx)
	return headers.Get(RequestIDHeaderHTTP)
}

// NewFlowStarterContext decorates the given context with a
// request id and marks it as an internal request.
func NewFlowStarterContext(ctx context.Context) context.Context {
	return NewFlowStarterContextUtil(ctx)
}
