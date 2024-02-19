package tracing

import (
	"context"
	"net/http"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
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

type Tracer struct {
	TraceID   uuid.UUID // TraceID is unique across the lifecycle of a single 'event', regardless of how many requests it takes to complete. Carried in the `X-Trace-ID` header.
	RequestID uuid.UUID // RequestID is unique to each request. Carried in the `X-Request-ID` header.
}

type key[T any] struct{} // key is a unique type that we can use as a key in a context

// WithValue returns a new context with the given value set. Only one value of each type can be set in a context; setting a value of the same type will overwrite the previous value.
func WithValue[T any](ctx context.Context, value T) context.Context {
	return context.WithValue(ctx, key[T]{}, value)
}

// Value returns the value of type T in the given context, or false if the context does not contain a value of type T.
func Value[T any](ctx context.Context) (T, bool) {
	value, ok := ctx.Value(key[T]{}).(T)
	return value, ok
}

// Trace returns a RoundTripFunc that
// - adds a trace to the request context
// - generating a new one if necessary
// - adds the X-Trace-ID and X-Request-ID headers to the request
// - then calls the next RoundTripper
func TraceMiddleware() gin.HandlerFunc {
	return func(c *gin.Context) {

		// does the request already have a trace? if so, use it. otherwise, generate a new one.
		traceID, err := uuid.Parse(c.GetHeader("X-Trace-ID"))
		if err != nil || traceID.String() == "" {
			traceID = uuid.New()
		}

		// build the trace. it's a small struct, so we put it directly in the context and don't bother with a pointer.
		trace := Tracer{TraceID: traceID, RequestID: uuid.New()}

		ctx := WithValue(c.Request.Context(), trace) // add trace to context; retrieve with ctxutil.Value[Trace](ctx)

		c.Request = c.Request.WithContext(ctx)

		// add trace id & request id to headers
		c.Request.Header.Set("X-Trace-ID", trace.TraceID.String())
		c.Set("X-Trace-ID", trace.TraceID.String())

		c.Header(("X-Request-ID"), trace.RequestID.String())
		c.Set(("X-Request-ID"), trace.RequestID.String())

		c.Next()
	}
}
