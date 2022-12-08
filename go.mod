module github.com/mccutchen/go-httpbin/v2

go 1.16

require (
	github.com/go-redis/redis/extra/redisotel/v9 v9.0.0-rc.2
	github.com/go-redis/redis/v9 v9.0.0-rc.2
	github.com/gorilla/handlers v1.5.1
	github.com/gorilla/mux v1.8.0
	github.com/labbsr0x/mux-monitor v1.0.0-rc
	github.com/matttproud/golang_protobuf_extensions v1.0.2-0.20181231171920-c182affec369 // indirect
	github.com/prometheus/client_golang v1.14.0
	go.opentelemetry.io/contrib/instrumentation/net/http/otelhttp v0.36.4
	go.opentelemetry.io/contrib/propagators/b3 v1.11.1
	go.opentelemetry.io/otel v1.11.1
	go.opentelemetry.io/otel/exporters/jaeger v1.11.1
	go.opentelemetry.io/otel/sdk v1.11.1
	go.opentelemetry.io/otel/trace v1.11.1
)
