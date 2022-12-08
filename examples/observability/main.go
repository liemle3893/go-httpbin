package main

import (
	"go.opentelemetry.io/contrib/propagators/b3"
	"go.opentelemetry.io/otel"
	"log"
	"net/http"
	"os"

	"github.com/mccutchen/go-httpbin/v2/httpbin"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/exporters/jaeger"
	"go.opentelemetry.io/otel/sdk/resource"
	tracesdk "go.opentelemetry.io/otel/sdk/trace"
	semconv "go.opentelemetry.io/otel/semconv/v1.12.0"
)

func tracerProvider(appName, jaegerEndpoint string) (*tracesdk.TracerProvider, error) {
	// Create the Jaeger exporter
	exp, err := jaeger.New(jaeger.WithCollectorEndpoint(jaeger.WithEndpoint(jaegerEndpoint)))
	if err != nil {
		return nil, err
	}
	tp := tracesdk.NewTracerProvider(
		// Always be sure to batch in production.
		tracesdk.WithBatcher(exp),
		// Record information about this application in a Resource.
		tracesdk.WithResource(resource.NewWithAttributes(
			semconv.SchemaURL,
			semconv.ServiceNameKey.String(appName),
			attribute.String("environment", "development"),
			attribute.Int64("ID", 123),
		)),
	)
	return tp, nil
}

func initOtel() {
	svc := os.Getenv("OTEL_SERVICE_NAME")
	if svc == "" {
		svc = "httpbin"
	}
	jaegerEndpoint := os.Getenv("JAEGER_ENDPOINT")
	if jaegerEndpoint == "" {
		jaegerEndpoint = "http://localhost:14268/api/traces"
	}
	tp, err := tracerProvider(svc, jaegerEndpoint)
	if err != nil {
		log.Fatal(err)
	}
	otel.SetTracerProvider(tp)
	otel.SetTextMapPropagator(b3.New())
}

func main() {
	initOtel()
	app := httpbin.New()
	mux := http.NewServeMux()
	mux.Handle("/", app.Handler())
	listenAddr := "0.0.0.0:8080"
	http.ListenAndServe(listenAddr, app)
}
