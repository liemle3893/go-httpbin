package httpbin

import (
	"errors"
	"github.com/gorilla/handlers"
	"github.com/gorilla/mux"
	muxMonitor "github.com/labbsr0x/mux-monitor"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/propagation"
	"net/http"
	"os"
	"strconv"
	"strings"
	"sync/atomic"
	"time"
)

// Default configuration values
const (
	DefaultMaxBodySize int64 = 1024 * 1024
	DefaultMaxDuration       = 10 * time.Second
	DefaultHostname          = "go-httpbin"
)

// DefaultParams defines default parameter values
type DefaultParams struct {
	DripDuration time.Duration
	DripDelay    time.Duration
	DripNumBytes int64
}

// DefaultDefaultParams defines the DefaultParams that are used by default. In
// general, these should match the original httpbin.org's defaults.
var DefaultDefaultParams = DefaultParams{
	DripDuration: 2 * time.Second,
	DripDelay:    2 * time.Second,
	DripNumBytes: 10,
}

// HTTPBin contains the business logic
type HTTPBin struct {
	// Max size of an incoming request generated response body, in bytes
	MaxBodySize int64

	// Max duration of a request, for those requests that allow user control
	// over timing (e.g. /delay)
	MaxDuration time.Duration

	// Observer called with the result of each handled request
	Observer Observer

	// Default parameter values
	DefaultParams DefaultParams

	// Set of hosts to which the /redirect-to endpoint will allow redirects
	AllowedRedirectDomains map[string]struct{}

	// The hostname to expose via /hostname.
	hostname string

	// The app's http handler
	handler http.Handler
}

// New creates a new HTTPBin instance
func New(opts ...OptionFunc) *HTTPBin {
	h := &HTTPBin{
		MaxBodySize:   DefaultMaxBodySize,
		MaxDuration:   DefaultMaxDuration,
		DefaultParams: DefaultDefaultParams,
		hostname:      DefaultHostname,
	}
	for _, opt := range opts {
		opt(h)
	}
	h.handler = h.Handler()
	return h
}

// ServeHTTP implememnts the http.Handler interface.
func (h *HTTPBin) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	h.handler.ServeHTTP(w, r)
}

// Assert that HTTPBin implements http.Handler interface
var _ http.Handler = &HTTPBin{}

// Handler returns an http.Handler that exposes all HTTPBin endpoints
func (h *HTTPBin) Handler() http.Handler {

	mux := mux.NewRouter()

	mux.HandleFunc("/", methods(h.Index, "GET"))
	mux.HandleFunc("/forms/post", methods(h.FormsPost, "GET"))
	mux.HandleFunc("/encoding/utf8", methods(h.UTF8, "GET"))

	mux.HandleFunc("/delete", methods(h.RequestWithBody, "DELETE"))
	mux.HandleFunc("/get", methods(h.Get, "GET"))
	mux.HandleFunc("/head", methods(h.Get, "HEAD"))
	mux.HandleFunc("/patch", methods(h.RequestWithBody, "PATCH"))
	mux.HandleFunc("/post", methods(h.RequestWithBody, "POST"))
	mux.HandleFunc("/put", methods(h.RequestWithBody, "PUT"))

	mux.HandleFunc("/anything", h.Anything)
	mux.HandleFunc("/anything/", h.Anything)

	mux.HandleFunc("/ip", h.IP)
	mux.HandleFunc("/user-agent", h.UserAgent)
	mux.HandleFunc("/headers", h.Headers)
	mux.HandleFunc("/response-headers", h.ResponseHeaders)
	mux.HandleFunc("/hostname", h.Hostname)

	mux.HandleFunc("/status/{status}", h.Status)
	mux.HandleFunc("/unstable", h.Unstable)

	mux.HandleFunc("/redirect/", h.Redirect)
	mux.HandleFunc("/relative-redirect/", h.RelativeRedirect)
	mux.HandleFunc("/absolute-redirect/", h.AbsoluteRedirect)
	mux.HandleFunc("/redirect-to", h.RedirectTo)

	mux.HandleFunc("/cookies", h.Cookies)
	mux.HandleFunc("/cookies/set", h.SetCookies)
	mux.HandleFunc("/cookies/delete", h.DeleteCookies)

	mux.HandleFunc("/basic-auth/", h.BasicAuth)
	mux.HandleFunc("/hidden-basic-auth/", h.HiddenBasicAuth)
	mux.HandleFunc("/digest-auth/", h.DigestAuth)
	mux.HandleFunc("/bearer", h.Bearer)

	mux.HandleFunc("/deflate", h.Deflate)
	mux.HandleFunc("/gzip", h.Gzip)

	mux.HandleFunc("/stream/", h.Stream)
	mux.HandleFunc("/delay/{delay}", h.Delay)
	mux.HandleFunc("/drip", h.Drip)

	mux.HandleFunc("/range/", h.Range)
	mux.HandleFunc("/bytes/", h.Bytes)
	mux.HandleFunc("/stream-bytes/", h.StreamBytes)

	mux.HandleFunc("/html", h.HTML)
	mux.HandleFunc("/robots.txt", h.Robots)
	mux.HandleFunc("/deny", h.Deny)

	mux.HandleFunc("/cache", h.Cache)
	mux.HandleFunc("/cache/", h.CacheControl)
	mux.HandleFunc("/etag/", h.ETag)

	mux.HandleFunc("/links/", h.Links)

	mux.HandleFunc("/image", h.ImageAccept)
	mux.HandleFunc("/image/", h.Image)
	mux.HandleFunc("/xml", h.XML)
	mux.HandleFunc("/json", h.JSON)

	mux.HandleFunc("/uuid", h.UUID)
	mux.HandleFunc("/base64/", h.Base64)

	// existing httpbin endpoints that we do not support
	mux.HandleFunc("/brotli", notImplementedHandler)

	// Export metrics for prometheus
	mux.Handle("/metrics", promhttp.Handler())
	// Custom endpoint to get the current version of the app
	mux.HandleFunc("/upstream", h.upstreamGet)
	mux.HandleFunc("/redis", h.handleRedisCall)

	// Make sure our ServeMux doesn't "helpfully" redirect these invalid
	// endpoints by adding a trailing slash. See the ServeMux docs for more
	// info: https://golang.org/pkg/net/http/#ServeMux
	mux.HandleFunc("/absolute-redirect", http.NotFound)
	mux.HandleFunc("/basic-auth", http.NotFound)
	mux.HandleFunc("/delay", http.NotFound)
	mux.HandleFunc("/digest-auth", http.NotFound)
	mux.HandleFunc("/hidden-basic-auth", http.NotFound)
	mux.HandleFunc("/redirect", http.NotFound)
	mux.HandleFunc("/relative-redirect", http.NotFound)
	mux.HandleFunc("/status", http.NotFound)
	mux.HandleFunc("/stream", http.NotFound)
	mux.HandleFunc("/bytes", http.NotFound)
	mux.HandleFunc("/stream-bytes", http.NotFound)
	mux.HandleFunc("/links", http.NotFound)

	//mux.Use(func(handler http.Handler) http.Handler {
	//	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
	//
	//		w.Header().Set("Server", "httpbin")
	//		handler.ServeHTTP(w, r)
	//	})
	//})
	mux.Use(_monitor.Observability)
	mux.Use(func(handler http.Handler) http.Handler {
		return handlers.CustomLoggingHandler(os.Stdout, handler, writeCombinedLog)
	})
	var handler http.Handler
	handler = mux
	handler = limitRequestSize(h.MaxBodySize, handler)
	handler = preflight(handler)
	handler = autohead(handler)
	if h.Observer != nil {
		handler = observe(h.Observer, handler)
	}

	return handler
}

var (
	_monitor, _ = newMonitor("v1.0.0", muxMonitor.DefaultErrorMessageKey)
)

type monitor struct {
	reqDuration           *prometheus.HistogramVec
	dependencyReqDuration *prometheus.HistogramVec
	respSize              *prometheus.CounterVec
	dependencyUP          *prometheus.GaugeVec
	applicationInfo       *prometheus.GaugeVec
	errorMessageKey       string
	IsStatusError         func(statusCode int) bool
}

// DependencyStatus is the type to represent UP or DOWN states
type DependencyStatus int

// DependencyChecker specifies the methods a checker must implement.
type DependencyChecker interface {
	GetDependencyName() string
	Check() DependencyStatus
}

const defaultErrorMessageKey = "error-message"

var (
	defaultBuckets = []float64{0.005, 0.01, 0.025, 0.05, 0.075, 0.1, 0.25, 0.5, 0.75, 1, 2.5, 5, 7.5, 10}
)

func newMonitor(applicationVersion string, errorMessageKey string) (*monitor, error) {
	if strings.TrimSpace(applicationVersion) == "" {
		return nil, errors.New("application version must be a non-empty string")
	}
	if strings.TrimSpace(applicationVersion) == "" {
		errorMessageKey = defaultErrorMessageKey
	}
	monitor := &monitor{errorMessageKey: errorMessageKey, IsStatusError: isStatusError}
	monitor.reqDuration = promauto.NewHistogramVec(prometheus.HistogramOpts{
		Name:    "myapp_request_seconds",
		Help:    "Duration in seconds of HTTP requests.",
		Buckets: defaultBuckets,
	}, []string{"type", "status", "method", "addr", "isError", "errorMessage"})
	monitor.respSize = promauto.NewCounterVec(prometheus.CounterOpts{
		Name: "myapp_response_size_bytes",
		Help: "Counts the size of each HTTP response",
	}, []string{"type", "status", "method", "addr", "isError", "errorMessage"})
	monitor.dependencyUP = promauto.NewGaugeVec(prometheus.GaugeOpts{
		Name: "myapp_dependency_up",
		Help: "Records if a dependency is up or down. 1 for up, 0 for down",
	}, []string{"name"})
	monitor.dependencyReqDuration = promauto.NewHistogramVec(prometheus.HistogramOpts{
		Name:    "myapp_dependency_request_seconds",
		Help:    "Duration of dependency requests in seconds.",
		Buckets: defaultBuckets,
	}, []string{"name", "type", "status", "method", "addr", "isError", "errorMessage"})

	monitor.applicationInfo = promauto.NewGaugeVec(prometheus.GaugeOpts{
		Name: "myapp_application_info",
		Help: "Static information about the application",
	}, []string{"version"})
	monitor.applicationInfo.WithLabelValues("v1.0.0").Set(1)
	return monitor, nil
}

func (m *monitor) collectTime(reqType, status, method, addr, isError, errorMessage string, durationSeconds float64) {
	m.reqDuration.WithLabelValues(reqType, status, method, addr, isError, errorMessage).Observe(durationSeconds)
}

func (m *monitor) collectSize(reqType, status, method, addr, isError, errorMessage string, size float64) {
	m.respSize.WithLabelValues(reqType, status, method, addr, isError, errorMessage).Add(size)
}

// CollectDependencyTime collet the duration of dependency requests in seconds
func (m *monitor) CollectDependencyTime(name, reqType, status, method, addr, isError, errorMessage string, durationSeconds float64) {
	m.dependencyReqDuration.WithLabelValues(name, reqType, status, method, addr, isError, errorMessage).Observe(durationSeconds)
}

// Observability implements mux.MiddlewareFunc.
func (m *monitor) Observability(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		respWriter := newResponseWriter(w)
		route := mux.CurrentRoute(r)
		path, _ := route.GetPathTemplate()
		ctx := otel.GetTextMapPropagator().Extract(r.Context(), propagation.HeaderCarrier(r.Header))
		ctx, span := otel.Tracer("myapp.http_request").Start(ctx, path)
		defer span.End()

		// decorate the request with the new context
		r = r.WithContext(ctx)
		next.ServeHTTP(respWriter, r)
		duration := time.Since(respWriter.started)
		statusCodeStr := respWriter.StatusCodeStr()
		isErrorStr := strconv.FormatBool(m.IsStatusError(respWriter.statusCode))
		// Set span attributes
		span.SetAttributes(
			attribute.String("http.method", r.Method),
			attribute.String("http.path", r.URL.Path),
			attribute.String("http.status_code", statusCodeStr),
		)
		errorMessage := r.Header.Get(m.errorMessageKey)
		r.Header.Del(m.errorMessageKey)
		m.collectTime(r.Proto, statusCodeStr, r.Method, path, isErrorStr, errorMessage, duration.Seconds())
		m.collectSize(r.Proto, statusCodeStr, r.Method, path, isErrorStr, errorMessage, float64(respWriter.Count()))
	})
}

// AddDependencyChecker creates a ticker that periodically executes the checker and collects the dependency state metrics
func (m *monitor) AddDependencyChecker(checker DependencyChecker, checkingPeriod time.Duration) {
	ticker := time.NewTicker(checkingPeriod)
	go func() {
		for range ticker.C {
			status := checker.Check()
			m.dependencyUP.WithLabelValues(checker.GetDependencyName()).Set(float64(status))
		}
	}()
}

func isStatusError(statusCode int) bool {
	return statusCode < 200 || statusCode >= 400
}

// workaround to get status code on middleware
type responseWriter struct {
	http.ResponseWriter
	started    time.Time
	statusCode int
	count      uint64
}

func newResponseWriter(w http.ResponseWriter) *responseWriter {
	// WriteHeader(int) is not called if our response implicitly returns 200 OK, so
	// we default to that status code.
	return &responseWriter{
		ResponseWriter: w,
		statusCode:     http.StatusOK,
		started:        time.Now(),
	}
}

func (r *responseWriter) StatusCode() int {
	return r.statusCode
}

func (r *responseWriter) StatusCodeStr() string {
	return strconv.Itoa(r.statusCode)
}

// Write returns underlying Write result, while counting data size
func (r *responseWriter) Write(b []byte) (int, error) {
	n, err := r.ResponseWriter.Write(b)
	atomic.AddUint64(&r.count, uint64(n))
	return n, err
}

func (r *responseWriter) WriteHeader(code int) {
	r.statusCode = code
	r.ResponseWriter.WriteHeader(code)
}

// Count function return counted bytes
func (r *responseWriter) Count() uint64 {
	return atomic.LoadUint64(&r.count)
}
