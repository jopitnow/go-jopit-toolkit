package telemetry

import (
	"context"
	"fmt"

	otellog "go.opentelemetry.io/otel/log"
	"go.opentelemetry.io/otel/sdk/log"
	sdklog "go.opentelemetry.io/otel/sdk/log"

	"go.opentelemetry.io/otel/exporters/otlp/otlplog/otlploghttp"
	"go.opentelemetry.io/otel/log/global"
)

var LoggerProvider otellog.Logger

func InitLoggerExporter(apiName string) (func(context.Context) error, error) {
	ctx := context.Background()

	// Configure OTLP log exporter
	exporter, err := otlploghttp.New(ctx, otlploghttp.WithEndpointURL("http://localhost:4318/v1/logs"))
	if err != nil {
		return nil, fmt.Errorf("WARNING: error initiating the otlp exporter for logs: ", err.Error())
	}

	// Create the logger provider
	lp := log.NewLoggerProvider(
		log.WithProcessor(
			log.NewBatchProcessor(exporter),
		),
	)

	var _ sdklog.Exporter = (*otlploghttp.Exporter)(nil)

	global.SetLoggerProvider(lp)

	// Emit a log record
	//record := otellog.Record{}
	//record.SetSeverity(otellog.SeverityInfo)                        // Set severity level
	//record.SetTimestamp(time.Now())                                 // Set timestamp
	//record.SetBody(otellog.StringValue("OTLP logging is working!")) // Log message
	//record.AddAttributes(otellog.String("status", "successful"))

	// Create logger from provider
	serviceName := fmt.Sprintf("%s-logger", apiName)
	LoggerProvider = lp.Logger(serviceName)

	return lp.Shutdown, nil
}
