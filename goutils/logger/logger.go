/**
* @author mnunez
 */

package logger

import (
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"runtime/debug"
	"strings"
	"time"

	"github.com/sirupsen/logrus"
	prefixed "github.com/x-cray/logrus-prefixed-formatter"
)

var Log *logrus.Logger

const tagMessageFormat = "%s - %s"

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
	Name       string      `json:"name"`
	Body       interface{} `json:"body"`
	Headers    http.Header `json:"headers"`
	UserID     *string     `json:"user_id"`
	AuthHeader bool        `json:"authorization_header"`
}

type Response struct {
	Status      int         `json:"status"`
	StatusGroup string      `json:"status_group"`
	TimeMS      string      `json:"time_ms"`
	Body        interface{} `json:"body"`
	Headers     http.Header `json:"headers"`
}

func InitLog(loggingPath, loggingFile, loggingLevel string) {
	Log = logrus.New()
	// Creating log dir if not exists
	if _, err := os.Stat(loggingPath); os.IsNotExist(err) {
		if err = os.MkdirAll(loggingPath, 0777); err != nil {
			if os.IsPermission(err) {
				fmt.Println("Try fix the permission issue, by creating the dir structure and try again.")
				panic(err)
			}
		}
	}

	f := filepath.Join(loggingPath, loggingFile)
	fmt.Printf("Logging on : %s\n", f)
	file, err := os.OpenFile(f, os.O_RDWR|os.O_CREATE|os.O_APPEND, 0777)
	if err == nil {
		Log.SetOutput(file)
	} else {
		fmt.Println("Failed to log to file, using default stderr : ", err)
		Log.SetOutput(os.Stderr)
	}
	Log.SetOutput(file)
	// Log as JSON instead of the default ASCII formatter.
	Log.Formatter = new(prefixed.TextFormatter)
	Log.Formatter.(*prefixed.TextFormatter).ForceFormatting = true
	Log.Formatter.(*prefixed.TextFormatter).FullTimestamp = true

	// Only log the warning severity or above.
	lvl, err := logrus.ParseLevel(loggingLevel)
	if err != nil {
		lvl = logrus.InfoLevel
	}
	Log.SetLevel(lvl)
}

func Print(e interface{}) {
	Log.Printf("%s: %s", e, debug.Stack())
}

func Debug(message string, tags ...string) {
	if Log.Level > logrus.DebugLevel {
		tags = append(tags, "level:debug")
		entry, message := buildLogEntryWithMessage(tags, message)
		entry.Debug(message)
	}
}

func Info(message string, tags ...string) {
	if Log.Level > logrus.InfoLevel {
		tags = append(tags, "level:info")
		entry, message := buildLogEntryWithMessage(tags, message)
		entry.Info(message)
	}
}

func Warn(message string, tags ...string) {
	if Log.Level > logrus.WarnLevel {
		tags = append(tags, "level:warn")
		entry, message := buildLogEntryWithMessage(tags, message)
		entry.Info(message)
	}
}

func Error(message string, err error, tags ...string) {
	if Log.Level > logrus.ErrorLevel {
		tags = append(tags, "level:error")
		msg := fmt.Sprintf("%s - ERROR: %v", message, err)
		entry, msg := buildLogEntryWithMessage(tags, msg)
		entry.Error(msg)
	}
}

func Panic(message string, err error, tags ...string) {
	if Log.Level > logrus.PanicLevel {
		tags = append(tags, "level:panic")
		msg := fmt.Sprintf("%s - PANIC: %v", message, err)
		entry, msg := buildLogEntryWithMessage(tags, msg)
		entry.Panic(msg)
	}
}

func Debugf(format string, args ...interface{}) {
	if Log.Level > logrus.DebugLevel {
		Debug(fmt.Sprintf(format, args...))
	}
}

func Infof(format string, args ...interface{}) {
	if Log.Level > logrus.InfoLevel {
		Info(fmt.Sprintf(format, args...))
	}
}

func Warnf(format string, args ...interface{}) {
	if Log.Level > logrus.WarnLevel {
		Warn(fmt.Sprintf(format, args...))
	}
}

func Errorf(format string, err error, args ...interface{}) {
	if Log.Level > logrus.ErrorLevel {
		Error(fmt.Sprintf(format, args...), err)
	}
}

func Panicf(format string, err error, args ...interface{}) {
	if Log.Level > logrus.PanicLevel {
		Panic(fmt.Sprintf(format, args...), err)
	}
}

func GetOut() io.Writer {
	return Log.Out
}

func buildLogEntryWithMessage(tags []string, message string) (*logrus.Entry, string) {
	fields, err := getFields(tags)
	if err != nil {
		message = fmt.Sprintf(tagMessageFormat, message, err.Error())
	}
	return Log.WithFields(fields), message
}

func getFields(tags []string) (logrus.Fields, error) {
	fields := make(logrus.Fields)
	wrongTags := []string{}
	var err error

	for _, value := range tags {
		values := strings.SplitN(value, ":", 2)

		if len(values) < 2 {
			wrongTags = append(wrongTags, value)
			continue
		}

		fields[strings.TrimSpace(values[0])] = strings.TrimSpace(values[1])
	}

	if len(wrongTags) > 0 {
		err = fmt.Errorf("Error parsing tags (%s)", strings.Join(wrongTags, ","))
	}

	return fields, err
}
