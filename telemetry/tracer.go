package telemetry

import (
	"context"
	"os"
	"strings"
	"time"

	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/exporters/otlp/otlptrace/otlptracehttp"
	"go.opentelemetry.io/otel/propagation"
	"go.opentelemetry.io/otel/sdk/resource"
	sdktrace "go.opentelemetry.io/otel/sdk/trace"

	"go.opentelemetry.io/otel/trace"
)

func InitTracerExporter(apiName string) (func(context.Context) error, error) {
	ctx := context.Background()

	exporter, err := otlptracehttp.New(ctx, otlptracehttp.WithTimeout(10*time.Second), otlptracehttp.WithEndpointURL("http://jopit-otel-exporter:4318/v1/traces"))
	if err != nil {
		return nil, err
	}

	parts := strings.Split(os.Getenv("DEPLOY_ENVIRONMENT"), "-")

	env := parts[0]
	version := parts[1]

	// Optionally define a resource to add attributes like service.name.
	res, err := resource.New(ctx,
		resource.WithAttributes(
			attribute.String("service.name", apiName+"-api"),
			attribute.String("service.version", version),
			attribute.String("deployment.environment", env), //to-do
		),
	)
	if err != nil {
		return nil, err
	}

	tp := sdktrace.NewTracerProvider(
		sdktrace.WithSampler(sdktrace.AlwaysSample()),
		sdktrace.WithBatcher(exporter),
		sdktrace.WithResource(res),
	)
	otel.SetTextMapPropagator(propagation.TraceContext{})
	otel.SetTracerProvider(tp)
	return tp.Shutdown, nil
}

func GetTraceIDFromContext(ctx context.Context) string {
	span := trace.SpanFromContext(ctx)
	if !span.SpanContext().IsValid() {
		return "No trace ID found in context"
	}
	return span.SpanContext().TraceID().String()
}
