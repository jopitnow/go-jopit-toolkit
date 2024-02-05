package logger

import (
	"bytes"
	"context"
	"fmt"
	"github.com/gin-gonic/gin"
	"io"
	"math/rand"
	"sort"
	"strconv"
	"strings"
	"time"
)

type contextKey string

const requestLoggerKey = contextKey("request_logger")

type RequestLogger interface {
	LogResponse(c *gin.Context)
}

type requestLogger struct {
	Values       map[string]string
	LogRatio     int32
	LogBodyRatio int32
	StartTime    time.Time
	BodyWriter   *responseBodyWriter
	BodyInput    string
}

type responseBodyWriter struct {
	gin.ResponseWriter
	body *bytes.Buffer
}

func (r responseBodyWriter) Write(b []byte) (int, error) {
	r.body.Write(b)
	return r.ResponseWriter.Write(b)
}

func NewRequestLogger(c *gin.Context, requestName string, logRatio, logBodyRatio int32) *requestLogger {
	w := &responseBodyWriter{body: bytes.NewBufferString(""), ResponseWriter: c.Writer}
	c.Writer = w
	reqLogger := &requestLogger{
		Values:       make(map[string]string),
		LogRatio:     logRatio,
		LogBodyRatio: logBodyRatio,
		StartTime:    time.Now(),
		BodyWriter:   w,
	}

	reqLogger.setRequestValues(c, requestName)
	c.Request = c.Request.WithContext(context.WithValue(c.Request.Context(), requestLoggerKey, reqLogger))
	return reqLogger
}

func (r *requestLogger) getResponseTimeMilliseconds() int64 {
	return time.Since(r.StartTime).Milliseconds()
}

func (r *requestLogger) setRequestValues(c *gin.Context, requestName string) {
	r.Values["request_user_id"] = c.Request.Header.Get("Authorization")
	r.Values["request_name"] = requestName
	r.Values["request_method"] = c.Request.Method
	r.Values["request_body_size"] = strconv.Itoa(int(c.Request.ContentLength))
	r.Values["request_url"] = c.Request.RequestURI
	r.BodyInput = r.saveBody(c)
}

func (r *requestLogger) LogResponse(c *gin.Context) {
	responseStatus := strconv.Itoa(c.Writer.Status())
	r.Values["response_time"] = strconv.FormatInt(r.getResponseTimeMilliseconds(), 10) + "ms"
	r.Values["response_status"] = responseStatus
	r.Values["response_status_group"] = responseStatus[0:1] + "XX"
	if c.Writer.Status() >= 400 || !logLimiter(r.LogBodyRatio) {
		r.Values["request_body"] = r.BodyInput
	}
	if c.Writer.Status() >= 400 {
		responseError := r.BodyWriter.body.String()
		r.Values["response_error"] = responseError
		r.logError()
	} else if !logLimiter(r.LogRatio) {
		r.logInfo()
	}
}

func (r *requestLogger) logInfo() {
	message := r.BuildLogMessage()
	Info(message)
}

func (r *requestLogger) logError() {
	message := r.BuildLogMessage()
	Error(message, nil)
}

func (r *requestLogger) BuildLogMessage() string {
	message := "RequestLogger "

	var logKeys []string
	for k := range r.Values {
		logKeys = append(logKeys, k)
	}
	sort.Strings(logKeys)

	for _, key := range logKeys {
		if len(r.Values[key]) > 0 && key != "message" && key != "request_body" && key != "response_error" {
			message += fmt.Sprintf("[%s:%s]", key, r.Values[key])
		}
	}

	message += r.getLogMessageByKey("request_body")
	message += r.getLogMessageByKey("response_error")
	message += strings.Replace(r.getLogMessageByKey("message"), "\"", "'", -1)
	return message
}

func (r *requestLogger) getLogMessageByKey(key string) string {
	if r.Values[key] != "" {
		return fmt.Sprintf(" - %s: %s", key, r.Values[key])
	}
	return ""
}

func logLimiter(limitValue int32) bool {
	if limitValue == 100 || limitValue == 0 {
		return limitValue == 0
	}
	return rand.Int31n(100) > limitValue
}

func (r *requestLogger) saveBody(c *gin.Context) string {
	var bodyBytes []byte
	if c.Request.Body != nil {
		bodyBytes, _ = io.ReadAll(c.Request.Body)
		// Restore the io.ReadCloser to its original state
		c.Request.Body = io.NopCloser(bytes.NewBuffer(bodyBytes))
	}
	return string(bodyBytes)
}

func GetFromContext(ctx context.Context) RequestLogger {
	var rlogger *requestLogger
	if ctx == nil {
		return rlogger
	}
	lg, ok := ctx.Value(requestLoggerKey).(RequestLogger)
	if !ok {
		return rlogger
	}
	return lg
}
