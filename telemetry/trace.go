package telemetry

import (
	"context"
	"time"

	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/exporters/otlp/otlptrace/otlptracehttp"
	"go.opentelemetry.io/otel/propagation"
	"go.opentelemetry.io/otel/sdk/resource"
	sdktrace "go.opentelemetry.io/otel/sdk/trace"
)

func InitTracer(apiName string) (func(context.Context) error, error) {
	ctx := context.Background()

	// Configure the exporter with the Tempo endpoint and authentication header.
	exporter, err := otlptracehttp.New(ctx, otlptracehttp.WithTimeout(10*time.Second))
	if err != nil {
		return nil, err
	}

	// Optionally define a resource to add attributes like service.name.
	res, err := resource.New(ctx,
		resource.WithAttributes(
			attribute.String("service.name", apiName+"-api"),
			//attribute.String("environment", "local"), //to-do
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
