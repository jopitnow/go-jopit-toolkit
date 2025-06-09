package telemetry

import (
	"context"
	"fmt"
	"os"
	"strings"

	"go.opentelemetry.io/otel/exporters/otlp/otlplog/otlploghttp"
	"go.opentelemetry.io/otel/log/global"
	sdklog "go.opentelemetry.io/otel/sdk/log"
	"go.opentelemetry.io/otel/sdk/resource"
	semconv "go.opentelemetry.io/otel/semconv/v1.4.0"
)

func InitLoggerExporter(apiName string) (func(context.Context) error, error) {
	ctx := context.Background()

	// Configure OTLP log exporter
	exporter, err := otlploghttp.New(ctx, otlploghttp.WithEndpointURL("http://jopit-otel-exporter:4318/v1/logs"))
	if err != nil {
		return nil, fmt.Errorf("WARNING: error initiating the otlp exporter for logs: ", err.Error())
	}

	parts := strings.Split(os.Getenv("DEPLOY_ENVIRONMENT"), "-")

	env := parts[0]
	version := parts[1]

	resource := resource.NewWithAttributes(
		semconv.SchemaURL,
		semconv.ServiceNameKey.String(apiName),
		semconv.ServiceVersionKey.String(version),
		semconv.DeploymentEnvironmentKey.String(env),
	)

	// Create log provider
	processor := sdklog.NewBatchProcessor(exporter)
	provider := sdklog.NewLoggerProvider(sdklog.WithProcessor(processor), sdklog.WithResource(resource))
	global.SetLoggerProvider(provider)

	return provider.Shutdown, nil
}
