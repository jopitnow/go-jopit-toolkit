package logger

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"math/rand"
	"net/http"
	"os"
	"strconv"
	"sync"
	"time"

	otellog "go.opentelemetry.io/otel/log"
	"go.opentelemetry.io/otel/log/global"

	"github.com/gin-gonic/gin"
	"github.com/jopitnow/go-jopit-toolkit/telemetry"
)

var logCount int
var mu sync.Mutex // Mutex to prevent race conditions for counter

var gcl *grafanaCloudLogger = &grafanaCloudLogger{}

type grafanaCloudLogger struct {
	Provider      otellog.Logger
	LogEntry      LogEntry
	SamplingLevel float64
	LoggingConfig int
	Limiter       int
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

func InitLoggerJopitConfig(apiname string) {

	loggingConfig := os.Getenv("LOGGING_CONFIG_LEVEL") //Which type of logs to make, ex.: 0 for all logs, 1 for FATAl and ERROR logs
	samplinlLevel := os.Getenv("LOGGING_SAMPLING_LEVEL")
	limiter := os.Getenv("LOGGING_LIMITER")

	lc, lcerr := strconv.Atoi(loggingConfig)
	sl, slerr := strconv.ParseFloat(samplinlLevel, 32)
	limit, limiterr := strconv.Atoi(limiter)

	if lcerr != nil {
		fmt.Println("WARNING: error casting LOGGING_CONFIG_LEVEL to int, implementing default value for LOGGING_CONFIG_LEVEL: 1")
		lc = 1
	}

	if slerr != nil {
		fmt.Println("WARNING: error casting LOGGING_SAMPLING_LEVEL to int, implementing default value for LOGGING_SAMPLING_LEVEL: 0.1")
		sl = 0.1
	}

	if limiterr != nil {
		fmt.Println("WARNING: error casting LOGGING_LIMITER to int, implementing default value for LOGGING_LIMITER: 1500")
		sl = 500
	}

	if lc < 0 || lc > 1 {
		fmt.Println("WARNING: invalid LOGGING_CONFIG_LEVEL value, implementing default value for LOGGING_CONFIG_LEVEL")
		lc = 1
	}

	if sl < 0 || sl > 1 {
		fmt.Println("WARNING: invalid LOGGING_SAMPLING_LEVEL value, implementing default value for LOGGING_SAMPLING_LEVEL")
		sl = 0.1
	}

	fmt.Println("Logging Mode:", lc)
	fmt.Println("Sampling Level:", sl)

	gcl.LoggingConfig = lc
	gcl.SamplingLevel = sl
	gcl.Limiter = limit

	lp := global.GetLoggerProvider()

	gcl.Provider = lp.Logger(apiname)
}

func LoggerGrafanaMiddleware() gin.HandlerFunc {
	return func(c *gin.Context) {

		if getLogCount() >= gcl.Limiter {
			fmt.Println("WARNING: limit for logs reached!!")
			return
		}

		//to grab the response body
		recorder := &responseBodyWriter{
			body:           bytes.NewBufferString(""),
			ResponseWriter: c.Writer,
		}
		c.Writer = recorder

		t := time.Now()
		t.Format("RFC1123")

		gcl.LogEntry = LogEntry{}
		gcl.LogEntry.Timestamp = t
		gcl.LogEntry.TraceID = telemetry.GetTraceIDFromContext(c.Request.Context())

		request := Request{}
		request.SetRequestValues(c)

		gcl.LogEntry.Request = request

		c.Next()

		response := Response{}
		response.SetResponseValues(c, t, recorder)

		gcl.LogEntry.Response = response

		if c.Writer.Status() >= 400 && c.Writer.Status() < 500 {
			gcl.LogEntry.Level = "ERROR"
		} else if c.Writer.Status() >= 500 {
			gcl.LogEntry.Level = "FATAL"
		} else {
			gcl.LogEntry.Level = "INFO"
		}

		if gcl.LogEntry.Level == "INFO" {

			if gcl.LoggingConfig == 0 { //if the configLevel is 0 means that all logs have to be sent.

				gcl.SendLogs(c.Request.Context())
				return

			} else if gcl.LoggingConfig == 1 { //if the configLevel is 0 only a percentage are sent. .

				if shouldLog(int(gcl.SamplingLevel)) {
					gcl.SendLogs(c.Request.Context())
					return
				}
			}

		} else if gcl.LogEntry.Level != "INFO" { //all FATAL and ERROR are meant to be sent at all times.
			gcl.SendLogs(c.Request.Context())
		}

	}
}

func (r *Response) SetResponseValues(c *gin.Context, t time.Time, responseRecorder *responseBodyWriter) {

	stringBody := responseRecorder.body.String()

	responseStatus := strconv.Itoa(c.Writer.Status())

	r.Status = c.Writer.Status()
	r.StatusGroup = responseStatus[0:1] + "XX"
	r.TimeMS = strconv.FormatInt(time.Since(t).Milliseconds(), 10) + "ms"
	r.Body = stringBody
	r.Headers = c.Writer.Header()
}

func (r *Request) SetRequestValues(c *gin.Context) {

	userID, _ := c.Get("user_id")
	userid := fmt.Sprint(userID)

	firebaseAuthExists := (c.Request.Header.Get("Authorization") != "")

	//Deleted the Auth from the header request for security porpouses.
	reqHeaders := c.Request.Header
	reqHeaders.Del("Authorization")

	r.Method = c.Request.Method
	r.URL = c.Request.RequestURI
	r.RemoteAddr = c.Request.RemoteAddr
	r.Body = r.requestBodyToJSON(c)
	r.Headers = c.Request.Header
	r.UserID = &userid
	r.AuthHeader = firebaseAuthExists
}

func (r *Request) requestBodyToJSON(c *gin.Context) string {
	var bodyBytes []byte
	if c.Request.Body != nil {
		bodyBytes, err := io.ReadAll(c.Request.Body)
		if err != nil {
			fmt.Println("WARNING: error reading the c.Request.Body: ", err)
		}
		// Restore the io.ReadCloser to its original state
		c.Request.Body = io.NopCloser(bytes.NewBuffer(bodyBytes))
	}
	return string(bodyBytes)
}

func (g *grafanaCloudLogger) SendLogs(ctx context.Context) {

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

	gcl.Provider.Emit(ctx, record)
}

func shouldLog(percentage int) bool {
	return rand.Intn(100) < percentage*100
}

func incrementLogCount() {
	mu.Lock()
	logCount++
	mu.Unlock()
}

func getLogCount() int {
	mu.Lock()
	defer mu.Unlock()
	return logCount
}
