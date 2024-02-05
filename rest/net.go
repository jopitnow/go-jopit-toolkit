package rest

import (
	"bytes"
	"compress/gzip"
	"encoding/json"
	"encoding/xml"
	"errors"
	"fmt"
	"io"
	"io/ioutil"
	"mime/multipart"
	"net"
	"net/http"
	"net/url"
	"path"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/agustinrabini/go-toolkit/tracing"
)

// We need to consume response bodies to maintain http connections, but
// limit the size we consume to respReadLimit.
const respReadLimit = int64(4096)

const RETRY_HEADER = "X-Retry"

var cacheableVerbs = map[string]struct{}{
	http.MethodGet:     struct{}{},
	http.MethodHead:    struct{}{},
	http.MethodOptions: struct{}{},
}
var defaultCheckRedirectFunc func(req *http.Request, via []*http.Request) error
var poolMap sync.Map

func (rb *RequestBuilder) DoRequest(verb string, reqURL string, reqBody interface{}, opts ...Option) *Response {
	var after func(bool)

	var reqOpt reqOptions

	for _, opt := range opts {
		opt(&reqOpt)
	}

	result := rb.doRequest(verb, reqURL, reqBody, reqOpt)

	if after != nil {
		success := result.Err == nil && result.StatusCode/100 != 5
		after(success)
	}

	return result
}

func (rb *RequestBuilder) doRequest(verb string, requestURL string, reqBody interface{}, opt reqOptions) (result *Response) {
	result = new(Response)
	requestURL = rb.BaseURL + requestURL

	// Marshal request to JSON or XML
	body, err := rb.marshalReqBody(reqBody)
	if err != nil {
		result.Err = err
		return
	}

	// Parse URL and to point to Mockup server if applicable
	resourceURL, err := parseURL(requestURL)
	if err != nil {
		result.Err = err
		return
	}

	// Response objects
	var httpResp *http.Response
	var responseErr error

	end := false
	retries := 0
	for !end {
		request, err := http.NewRequest(verb, resourceURL, bytes.NewBuffer(body))
		if err != nil {
			result.Err = err
			return
		}

		// Set extra parameters
		rb.setParams(request, requestURL)

		request.Header.Set(socketTimeoutConfig, millisString(rb.getRequestTimeout()))
		request.Header.Set(restClientPoolName, rb.poolName)

		// Copy headers from options struct into new request object.
		headers := opt.Headers()
		for k := range headers {
			request.Header.Add(k, headers.Get(k))
		}

		// Copy tracing headers from request context.
		traceHeaders := tracing.ForwardedHeaders(request.Context())
		for header := range traceHeaders {
			value := traceHeaders.Get(header)

			request.Header.Set(header, value)
		}

		httpResp, responseErr = rb.getClient().Do(request)

		if rb.RetryStrategy != nil {
			retryResp := rb.RetryStrategy.ShouldRetry(request, httpResp, responseErr, retries)
			if retryResp.Retry() {
				retryFunc := func() (interface{}, error) {
					// We might be retrying because of an error in the request. As stated
					// in https://godoc.org/net/http#Client.Do If the returned error
					// is nil, the Response will contain a non-nil Body which the
					// user is expected to close.
					if responseErr == nil {
						drainBody(httpResp.Body)
					}

					time.Sleep(retryResp.Delay())
					retries++
					request.Header.Set(RETRY_HEADER, strconv.Itoa(retries))
					return nil, nil
				}

				if _, err := retryLimiter.Action(1, retryFunc); err == nil {
					continue
				}

			}
		}
		end = true
	}

	if responseErr != nil {
		result.Err = responseErr
		return
	}

	// Read response
	defer httpResp.Body.Close()
	respBody, err := ioutil.ReadAll(httpResp.Body)

	if err != nil {
		result.Err = err
		return
	}

	result.Response = httpResp
	if !rb.UncompressResponse {
		result.byteBody = respBody
	} else {
		respEncoding := httpResp.Header.Get("Content-Encoding")
		if respEncoding == "" {
			respEncoding = httpResp.Header.Get("Content-Type")
		}
		switch respEncoding {
		case "gzip":
			fallthrough
		case "application/x-gzip":
			{
				if len(respBody) == 0 {
					break
				}
				gr, err := gzip.NewReader(bytes.NewBuffer(respBody))
				defer gr.Close()
				if err != nil {
					result.Err = err
				} else {
					uncompressedData, err := ioutil.ReadAll(gr)
					if err != nil {
						result.Err = err
					} else {
						result.byteBody = uncompressedData
					}
				}
			}
		default:
			{
				result.byteBody = respBody
			}
		}
	}
	return
}

// parseURL parses the URL to verify it is a valid one and returns
// the corresponding resource URL according to the environment
func parseURL(reqURL string) (string, error) {
	if mockUpEnv {
		rURL, err := url.Parse(reqURL)
		if err != nil {
			return reqURL, err
		}

		rURL.Scheme = mockServerURL.Scheme
		rURL.Host = mockServerURL.Host

		return rURL.String(), nil
	}

	return reqURL, nil
}

func (rb *RequestBuilder) marshalReqBody(body interface{}) (b []byte, err error) {
	if body != nil {
		switch rb.ContentType {
		case JSON:
			b, err = json.Marshal(body)
		case XML:
			b, err = xml.Marshal(body)
		case BYTES:
			var ok bool
			b, ok = body.([]byte)
			if !ok {
				err = fmt.Errorf("bytes: body is %T(%v) not a byte slice", body, body)
			}
		case MULTIPART:
			b, err = marshalMultipart(body)
		}
	}

	return
}

func marshalMultipart(body interface{}) ([]byte, error) {
	buffer, ok := body.(*bytes.Buffer)
	if !ok {
		return nil, fmt.Errorf("bytes: body is %T(%v) not a byte buffer", body, body)
	}

	if !isMultipartBuffer(buffer) {
		return nil, fmt.Errorf("bytes: body is %T(%v) not a multipart", body, body)
	}

	return buffer.Bytes(), nil
}

func isMultipartBuffer(buffer *bytes.Buffer) bool {
	writer := multipart.NewWriter(buffer)
	_, err := writer.CreateFormFile("file", "multipartTest")
	if err != nil {
		return false
	}

	return true
}

func (rb *RequestBuilder) getClient() *http.Client {
	// This will be executed only once
	// per request builder
	rb.clientMtxOnce.Do(func() {

		if rb.Client == nil {
			rb.Client = &http.Client{}
		}

		if rb.Client.Transport == nil {
			rb.Client.Timeout = rb.getRequestTimeout()
		}

		if !rb.FollowRedirect {
			rb.Client.CheckRedirect = func(req *http.Request, via []*http.Request) error {
				return errors.New("Avoided redirect attempt")
			}
		} else {
			rb.Client.CheckRedirect = defaultCheckRedirectFunc
		}
	})

	return rb.Client
}

func (rb *RequestBuilder) getTransport() http.RoundTripper {
	cp := rb.CustomPool
	if cp == nil {
		return rb.makeTransport()
	}

	cp.once.Do(func() {
		if cp.Transport == nil {
			cp.Transport = rb.makeTransport()
		} else if ctr, ok := cp.Transport.(*http.Transport); ok {
			ctr.DialContext = (&net.Dialer{Timeout: rb.getConnectionTimeout()}).DialContext
		}
	})

	return cp.Transport
}

func (rb *RequestBuilder) makeTransport() http.RoundTripper {
	return &http.Transport{
		MaxIdleConnsPerHost: rb.getMaxIdleConnsPerHost(),
		Proxy:               rb.getProxy(),
		DialContext:         (&net.Dialer{Timeout: rb.getConnectionTimeout()}).DialContext,
	}
}

func (rb *RequestBuilder) getRequestTimeout() time.Duration {
	switch {
	case rb.DisableTimeout:
		return 0
	case rb.Timeout > 0:
		return rb.Timeout
	default:
		return DefaultTimeout
	}
}

func (rb *RequestBuilder) getConnectionTimeout() time.Duration {
	switch {
	case rb.DisableTimeout:
		return 0
	case rb.ConnectTimeout > 0:
		return rb.ConnectTimeout
	default:
		return DefaultConnectTimeout
	}
}

func (rb *RequestBuilder) getMaxIdleConnsPerHost() int {
	if cp := rb.CustomPool; cp != nil {
		return cp.MaxIdleConnsPerHost
	}
	return DefaultMaxIdleConnsPerHost
}

func (rb *RequestBuilder) getProxy() func(*http.Request) (*url.URL, error) {
	if cp := rb.CustomPool; cp != nil && cp.Proxy != "" {
		if proxy, err := url.Parse(cp.Proxy); err == nil {
			return http.ProxyURL(proxy)
		}
	}
	return http.ProxyFromEnvironment
}

func (rb *RequestBuilder) setParams(req *http.Request, resourceURL string) {
	// Custom Headers
	if rb.Headers != nil && len(rb.Headers) > 0 {
		rb.headersMtx.RLock()
		for key, values := range rb.Headers {
			for _, value := range values {
				req.Header.Add(key, value)
			}
		}
		rb.headersMtx.RUnlock()
	}

	// Default headers
	req.Header.Set("Connection", "keep-alive")

	// If mockup
	if mockUpEnv {
		req.Header.Set("X-Original-URL", resourceURL)
	}

	// Basic Auth
	if rb.BasicAuth != nil {
		req.SetBasicAuth(rb.BasicAuth.UserName, rb.BasicAuth.Password)
	}

	// User Agent
	req.Header.Set("User-Agent", func() string {
		if rb.UserAgent != "" {
			return rb.UserAgent
		}
		return "github.com/go-loco/restful"
	}())

	// Encoding
	var cType string

	switch rb.ContentType {
	case JSON:
		cType = "json"
	case XML:
		cType = "xml"
	}

	if cType != "" {
		req.Header.Set("Accept", "application/"+cType)
		req.Header.Set("Content-Type", "application/"+cType)
	}
}

// Read & discard the given body until respReadLimit and close it.
//
// When a response body is given, closing it after EOF is reached
// means we can reuse the TCP connection.
//
// If the response body is bigger than respReadLimit then we give up and
// close the body, resulting in the connection being closed as well.
func drainBody(body io.ReadCloser) {
	defer body.Close()
	io.Copy(ioutil.Discard, io.LimitReader(body, respReadLimit))
}

func millisString(d time.Duration) string {
	return strconv.Itoa(int(d.Seconds() * 1000))
}

func getCallerFile() string {
	frame3 := getFrame(3)
	frame4 := getFrame(4)
	frame5 := getFrame(5)

	switch {
	case path.Base(frame4.File) == "rest.go":
		return "pool_" + strings.TrimSuffix(path.Base(frame5.File), ".go")
	case path.Base(frame3.File) == "requestbuilder.go":
		return "pool_" + strings.TrimSuffix(path.Base(frame4.File), ".go")
	case path.Base(frame3.File) == "concurrent.go":
		return "pool_concurrent_unknown"
	}

	return "pool_unknown"
}

func getFrame(skipFrames int) runtime.Frame {
	// We need the frame at index skipFrames+2, since we never want runtime.Callers and getFrame
	targetFrameIndex := skipFrames + 2

	// Set size to targetFrameIndex+2 to ensure we have room for one more caller than we need
	programCounters := make([]uintptr, targetFrameIndex+2)
	n := runtime.Callers(0, programCounters)

	frame := runtime.Frame{Function: "unknown"}
	if n > 0 {
		frames := runtime.CallersFrames(programCounters[:n])
		for more, frameIndex := true, 0; more && frameIndex <= targetFrameIndex; frameIndex++ {
			var frameCandidate runtime.Frame
			frameCandidate, more = frames.Next()
			if frameIndex == targetFrameIndex {
				frame = frameCandidate
			}
		}
	}
	return frame
}
