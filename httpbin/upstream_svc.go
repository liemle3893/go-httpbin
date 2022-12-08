/**
 * Created by liemlhd on 05/Dec/2022
 */

package httpbin

import (
	"context"
	"go.opentelemetry.io/contrib/instrumentation/net/http/otelhttp"
	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/codes"
	"io"
	"net/http"
)

var (
	defaultClient = &http.Client{
		Transport: otelhttp.NewTransport(http.DefaultTransport),
	}
)

// Get data from url
func Get(ctx context.Context, upstreamSvc string) (*http.Response, error) {
	ctx, span := otel.Tracer("myapp.http_client_request").Start(ctx, "http_client_request")
	defer span.End()
	req, err := http.NewRequest("GET", upstreamSvc, nil)
	span.SetAttributes(attribute.String("upstream_svc", upstreamSvc))
	if err != nil {
		span.SetStatus(codes.Error, err.Error())
		return nil, err
	}
	req = req.WithContext(ctx)
	resp, err := defaultClient.Do(req)
	if err != nil {
		span.SetStatus(codes.Error, err.Error())
		return nil, err
	}
	return resp, nil
}

func (h *HTTPBin) upstreamGet(w http.ResponseWriter, r *http.Request) {
	upstreamURL := r.URL.Query().Get("upstream_url")
	if upstreamURL == "" {
		http.Error(w, "upstream_url is required", http.StatusBadRequest)
		return
	}
	ctx := r.Context()
	resp, err := Get(ctx, upstreamURL)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	defer resp.Body.Close()
	dat, err := io.ReadAll(resp.Body)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", resp.Header.Get("Content-Type"))
	w.WriteHeader(resp.StatusCode)
	_, _ = w.Write(dat)
}
