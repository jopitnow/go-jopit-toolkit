package telemetry

import (
	// …
	"context"
	"os"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/exporters/otlp/otlpmetric/otlpmetrichttp"
	"go.opentelemetry.io/otel/metric"
	otelmetric "go.opentelemetry.io/otel/metric"
	sdkmetric "go.opentelemetry.io/otel/sdk/metric"
	"go.opentelemetry.io/otel/sdk/resource"
	// remove: "go.opentelemetry.io/otel/sdk/metric/reader"
)

// InitMeterExporter initializes OTLP‒HTTP metrics on the same pipeline as your traces/logs.
func InitMeterExporter(apiName string) (func(context.Context) error, error) {
	ctx := context.Background()

	exporter, err := otlpmetrichttp.New(ctx,
		otlpmetrichttp.WithEndpoint(os.Getenv("OTEL_EXPORTER_OTLP_ENDPOINT")+":4318"),
		otlpmetrichttp.WithTimeout(10*time.Second),
	)
	if err != nil {
		return nil, err
	}

	parts := strings.Split(os.Getenv("DEPLOY_ENVIRONMENT"), "-")

	env := parts[0]
	version := parts[1]

	// build your Resource as before…
	res, err := resource.New(ctx,
		resource.WithAttributes(
			attribute.String("service.name", "jopit-api-"+apiName),
			attribute.String("service.version", version),
			attribute.String("deployment.environment", env), //to-do
		),
	)
	if err != nil {
		return nil, err
	}

	// use the SDK’s built-in PeriodicReader
	reader := sdkmetric.NewPeriodicReader(exporter)

	// wire it up into the MeterProvider
	mp := sdkmetric.NewMeterProvider(
		sdkmetric.WithReader(reader),
		sdkmetric.WithResource(res),
	)
	otel.SetMeterProvider(mp)

	meter = otel.Meter("jopit-api-" + apiName)
	totalReqs, _ = meter.Int64Counter(
		"http.server.requests_total",
		otelmetric.WithDescription("Total HTTP requests"),
	)
	errorReqs, _ = meter.Int64Counter(
		"http.server.errors_total",
		otelmetric.WithDescription("Total HTTP 5xx responses"),
	)

	return mp.Shutdown, nil
}

var (
	meter        otelmetric.Meter = otel.Meter("")
	totalReqs, _                  = meter.Int64Counter("")
	errorReqs, _                  = meter.Int64Counter("")
)

func MetricsMiddleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		c.Next()

		route := c.FullPath()
		status := c.Writer.Status()
		attrs := []attribute.KeyValue{
			attribute.String("http.route", route),
			attribute.Int("http.status_code", status),
		}

		totalReqs.Add(
			c.Request.Context(),
			1,
			metric.WithAttributes(attrs...),
		)

		if c.Writer.Status() >= 500 && c.Writer.Status() < 600 {
			errorReqs.Add(
				c.Request.Context(),
				1,
				metric.WithAttributes(attrs...),
			)
		}
	}
}
