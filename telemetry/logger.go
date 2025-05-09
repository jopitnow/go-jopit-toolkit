package telemetry

import (
	"context"
	"fmt"

	otellog "go.opentelemetry.io/otel/log"

	"go.opentelemetry.io/otel/exporters/otlp/otlplog/otlploghttp"
	"go.opentelemetry.io/otel/log/global"
	sdklog "go.opentelemetry.io/otel/sdk/log"
)

var LoggerProvider *otellog.Logger

func InitLoggerExporter(apiName string) (func(context.Context) error, error) {
	ctx := context.Background()

	// Configure OTLP log exporter
	exporter, err := otlploghttp.New(ctx, otlploghttp.WithEndpointURL("http://localhost:4318/v1/logs"))
	if err != nil {
		return nil, fmt.Errorf("WARNING: error initiating the otlp exporter for logs: ", err.Error())
	}

	// Create log provider
	processor := sdklog.NewBatchProcessor(exporter)
	provider := sdklog.NewLoggerProvider(sdklog.WithProcessor(processor))
	global.SetLoggerProvider(provider)

	// Create logger from provider
	serviceName := fmt.Sprintf("%s", "-logger", apiName)
	l := provider.Logger(serviceName)
	LoggerProvider = &l

	return provider.Shutdown, nil
}
