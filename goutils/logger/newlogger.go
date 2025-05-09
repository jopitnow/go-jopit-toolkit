package logger

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"time"

	otellog "go.opentelemetry.io/otel/log"

	"github.com/gin-gonic/gin"
	"github.com/jopitnow/go-jopit-toolkit/telemetry"
)

var gCloudExporter grafanaCloudExporter = grafanaCloudExporter{
	Provider: telemetry.LoggerProvider,
}

type grafanaCloudExporter struct {
	Provider otellog.Logger
	LogEntry LogEntry
}

type LogEntry struct {
	Timestamp time.Time `json:"timestamp"`
	Level     string    `json:"level"`
	Message   string    `json:"message"`
	Request   Request   `json:"request"`
	Response  Response  `json:"response"`
	TraceID   string    `json:"trace_id"`
}

type Request struct {
	Method     string      `json:"method"`
	URL        string      `json:"url"`
	RemoteAddr string      `json:"remote_address"`
	Body       interface{} `json:"body"`
	Headers    http.Header `json:"headers"`
	UserID     *string     `json:"user_id"`
	AuthHeader bool        `json:"authorization_header"`
}

type Response struct {
	Status      int                 `json:"status"`
	StatusGroup string              `json:"status_group"`
	TimeMS      string              `json:"time_ms"`
	Body        interface{}         `json:"body"`
	Headers     http.Header         `json:"headers"`
	BodyWriter  *responseBodyWriter `json:"-"`
}

func LoggerGrafanaMiddleware() gin.HandlerFunc {
	return func(c *gin.Context) {

		t := time.Now()
		t.Format("RFC1123")

		gCloudExporter.LogEntry = LogEntry{}
		gCloudExporter.LogEntry.Timestamp = t
		gCloudExporter.LogEntry.TraceID = telemetry.GetTraceIDFromContext(c.Request.Context())

		request := Request{}
		request.SetRequestValues(c)

		gCloudExporter.LogEntry.Request = request

		c.Next()

		response := Response{}
		response.SetResponseValues(c, t)

		gCloudExporter.LogEntry.Response = response

		if c.Writer.Status() >= 400 {
			gCloudExporter.LogEntry.Level = "ERROR"
		} else if c.Writer.Status() >= 500 {
			gCloudExporter.LogEntry.Level = "FATAL"
		} else {
			gCloudExporter.LogEntry.Level = "INFO"
		}

		gCloudExporter.SendLogs(c.Request.Context())
	}
}

func (r *Response) SetResponseValues(c *gin.Context, t time.Time) {

	responseStatus := strconv.Itoa(c.Writer.Status())
	r = &Response{
		Status:      c.Writer.Status(),
		StatusGroup: responseStatus[0:1] + "XX",
		TimeMS:      strconv.FormatInt(time.Since(t).Milliseconds(), 10) + "ms",
		Body:        r.BodyWriter.body.String(),
		Headers:     c.Writer.Header(),
	}
}

func (r *Request) SetRequestValues(c *gin.Context) {

	userID, _ := c.Get("user_id")
	userid := fmt.Sprint(userID)

	firebaseAuthExists := (c.Request.Header.Get("Authorization") != "")

	//Deleted the Auth from the header request for security porpouses.
	reqHeaders := c.Request.Header
	reqHeaders.Del("Authorization")

	r = &Request{
		Method:     c.Request.Method,
		URL:        c.Request.RequestURI,
		RemoteAddr: c.Request.RemoteAddr,
		Body:       r.requestBodyToJSON(c),
		Headers:    c.Request.Header,
		UserID:     &userid,
		AuthHeader: firebaseAuthExists,
	}
}

func (r *Request) requestBodyToJSON(c *gin.Context) string {
	var bodyBytes []byte
	if c.Request.Body != nil {
		bodyBytes, _ = io.ReadAll(c.Request.Body)
		// Restore the io.ReadCloser to its original state
		c.Request.Body = io.NopCloser(bytes.NewBuffer(bodyBytes))
	}
	return string(bodyBytes)
}

func (g *grafanaCloudExporter) SendLogs(ctx context.Context) {

	record := otellog.Record{}

	logBytes, err := json.Marshal(g.LogEntry)
	if err != nil {
		fmt.Println("Error marshaling the log to json: ", err)
	}

	if g.LogEntry.Level == "ERROR" {
		record.SetSeverity(otellog.SeverityError)
	} else if g.LogEntry.Level == "FATAL" {
		record.SetSeverity(otellog.SeverityFatal)
	} else {
		record.SetSeverity(otellog.SeverityInfo)
	}

	record.SetTimestamp(g.LogEntry.Timestamp)
	record.SetBody(otellog.StringValue(string(logBytes)))

	telemetry.LoggerProvider.Emit(ctx, record)
}
