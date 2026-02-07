package metrics

import (
	"net/http"
	"strconv"
	"time"

	"github.com/gorilla/mux"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
)

var (
	// HTTP metrics
	httpRequestsTotal = promauto.NewCounterVec(
		prometheus.CounterOpts{
			Name: "http_requests_total",
			Help: "Total number of HTTP requests",
		},
		[]string{"method", "endpoint", "status"},
	)

	httpRequestDuration = promauto.NewHistogramVec(
		prometheus.HistogramOpts{
			Name:    "http_request_duration_seconds",
			Help:    "Duration of HTTP requests in seconds",
			Buckets: prometheus.DefBuckets,
		},
		[]string{"method", "endpoint"},
	)

	httpRequestSize = promauto.NewHistogramVec(
		prometheus.HistogramOpts{
			Name:    "http_request_size_bytes",
			Help:    "Size of HTTP requests in bytes",
			Buckets: prometheus.ExponentialBuckets(100, 10, 7), // 100B to 100MB
		},
		[]string{"method", "endpoint"},
	)

	httpResponseSize = promauto.NewHistogramVec(
		prometheus.HistogramOpts{
			Name:    "http_response_size_bytes",
			Help:    "Size of HTTP responses in bytes",
			Buckets: prometheus.ExponentialBuckets(100, 10, 7), // 100B to 100MB
		},
		[]string{"method", "endpoint"},
	)

	// Authentication metrics
	authAttemptsTotal = promauto.NewCounterVec(
		prometheus.CounterOpts{
			Name: "auth_attempts_total",
			Help: "Total number of authentication attempts",
		},
		[]string{"method", "status"}, // method: login, apikey, validate; status: success, failure
	)

	authDuration = promauto.NewHistogramVec(
		prometheus.HistogramOpts{
			Name:    "auth_duration_seconds",
			Help:    "Duration of authentication operations in seconds",
			Buckets: []float64{0.001, 0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1.0},
		},
		[]string{"method"},
	)

	// API Key metrics
	apikeyOperationsTotal = promauto.NewCounterVec(
		prometheus.CounterOpts{
			Name: "apikey_operations_total",
			Help: "Total number of API key operations",
		},
		[]string{"operation"}, // operation: create, list, delete, authenticate
	)

	// Database metrics
	dbOperationsTotal = promauto.NewCounterVec(
		prometheus.CounterOpts{
			Name: "db_operations_total",
			Help: "Total number of database operations",
		},
		[]string{"operation", "status"}, // operation: find, insert, update, delete; status: success, error
	)

	dbOperationDuration = promauto.NewHistogramVec(
		prometheus.HistogramOpts{
			Name:    "db_operation_duration_seconds",
			Help:    "Duration of database operations in seconds",
			Buckets: []float64{0.001, 0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1.0, 2.5, 5.0},
		},
		[]string{"operation"},
	)

	// Active connections (gauge)
	activeConnections = promauto.NewGauge(
		prometheus.GaugeOpts{
			Name: "active_connections",
			Help: "Number of active connections",
		},
	)
)

// HTTPMetricsMiddleware creates middleware to track HTTP metrics
func HTTPMetricsMiddleware() mux.MiddlewareFunc {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			start := time.Now()

			// Track active connections
			activeConnections.Inc()
			defer activeConnections.Dec()

			// Get route pattern for better labeling
			route := mux.CurrentRoute(r)
			var routeName string
			if route != nil {
				if name := route.GetName(); name != "" {
					routeName = name
				} else if path, err := route.GetPathTemplate(); err == nil {
					routeName = path
				} else {
					routeName = r.URL.Path
				}
			} else {
				routeName = r.URL.Path
			}

			// Track request size
			if r.ContentLength > 0 {
				httpRequestSize.WithLabelValues(r.Method, routeName).Observe(float64(r.ContentLength))
			}

			// Wrap response writer to track status and size
			wrapped := &responseWriter{ResponseWriter: w, statusCode: http.StatusOK}

			// Process request
			next.ServeHTTP(wrapped, r)

			// Calculate duration
			duration := time.Since(start).Seconds()

			// Record metrics
			status := strconv.Itoa(wrapped.statusCode)
			httpRequestsTotal.WithLabelValues(r.Method, routeName, status).Inc()
			httpRequestDuration.WithLabelValues(r.Method, routeName).Observe(duration)

			// Track response size if available
			if wrapped.size > 0 {
				httpResponseSize.WithLabelValues(r.Method, routeName).Observe(float64(wrapped.size))
			}
		})
	}
}

// responseWriter wraps http.ResponseWriter to track status and size
type responseWriter struct {
	http.ResponseWriter
	statusCode int
	size       int
}

func (rw *responseWriter) WriteHeader(code int) {
	rw.statusCode = code
	rw.ResponseWriter.WriteHeader(code)
}

func (rw *responseWriter) Write(b []byte) (int, error) {
	size, err := rw.ResponseWriter.Write(b)
	rw.size += size
	return size, err
}

// RecordAuthAttempt records an authentication attempt
func RecordAuthAttempt(method string, success bool) {
	status := "failure"
	if success {
		status = "success"
	}
	authAttemptsTotal.WithLabelValues(method, status).Inc()
}

// RecordAuthDuration records the duration of an authentication operation
func RecordAuthDuration(method string, duration time.Duration) {
	authDuration.WithLabelValues(method).Observe(duration.Seconds())
}

// RecordAPIKeyOperation records an API key operation
func RecordAPIKeyOperation(operation string) {
	apikeyOperationsTotal.WithLabelValues(operation).Inc()
}

// RecordDBOperation records a database operation
func RecordDBOperation(operation string, success bool, duration time.Duration) {
	status := "error"
	if success {
		status = "success"
	}
	dbOperationsTotal.WithLabelValues(operation, status).Inc()
	dbOperationDuration.WithLabelValues(operation).Observe(duration.Seconds())
}
