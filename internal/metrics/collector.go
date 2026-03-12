package metrics

import (
	"context"
	"os"

	"github.com/go-kratos/kratos/v2/log"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/tx7do/kratos-bootstrap/bootstrap"

	commonMetrics "github.com/go-tangra/go-tangra-common/metrics"
)

const namespace = "tangra"
const subsystem = "warden"

// Collector holds all Prometheus metrics for the warden module.
type Collector struct {
	log    *log.Helper
	server *commonMetrics.MetricsServer

	// Secret metrics
	SecretsByStatus *prometheus.GaugeVec

	// Folder metrics
	FoldersTotal prometheus.Gauge

	// Secret version metrics
	SecretVersionsTotal prometheus.Gauge
}

// NewCollector creates and registers all warden Prometheus metrics.
func NewCollector(ctx *bootstrap.Context) *Collector {
	c := &Collector{
		log: ctx.NewLoggerHelper("warden/metrics"),

		SecretsByStatus: prometheus.NewGaugeVec(prometheus.GaugeOpts{
			Namespace: namespace,
			Subsystem: subsystem,
			Name:      "secrets_by_status",
			Help:      "Number of secrets by status.",
		}, []string{"status"}),

		FoldersTotal: prometheus.NewGauge(prometheus.GaugeOpts{
			Namespace: namespace,
			Subsystem: subsystem,
			Name:      "folders_total",
			Help:      "Total number of folders.",
		}),

		SecretVersionsTotal: prometheus.NewGauge(prometheus.GaugeOpts{
			Namespace: namespace,
			Subsystem: subsystem,
			Name:      "secret_versions_total",
			Help:      "Total number of secret versions.",
		}),
	}

	prometheus.MustRegister(
		c.SecretsByStatus,
		c.FoldersTotal,
		c.SecretVersionsTotal,
	)

	addr := os.Getenv("METRICS_ADDR")
	if addr == "" {
		addr = ":9310"
	}
	c.server = commonMetrics.NewMetricsServer(addr, nil, ctx.GetLogger())

	go func() {
		if err := c.server.Start(); err != nil {
			c.log.Errorf("Metrics server failed: %v", err)
		}
	}()

	return c
}

// Stop shuts down the metrics HTTP server.
func (c *Collector) Stop(ctx context.Context) {
	if c.server != nil {
		c.server.Stop(ctx)
	}
}

// --- Secret helpers ---

// SecretCreated increments the secret counter for the given status.
func (c *Collector) SecretCreated(status string) {
	c.SecretsByStatus.WithLabelValues(status).Inc()
	c.SecretVersionsTotal.Inc() // initial version is created with the secret
}

// SecretDeleted decrements the secret counter for the given status.
func (c *Collector) SecretDeleted(status string) {
	c.SecretsByStatus.WithLabelValues(status).Dec()
}

// SecretStatusChanged adjusts the status gauge when a secret's status changes.
func (c *Collector) SecretStatusChanged(oldStatus, newStatus string) {
	c.SecretsByStatus.WithLabelValues(oldStatus).Dec()
	c.SecretsByStatus.WithLabelValues(newStatus).Inc()
}

// --- Folder helpers ---

// FolderCreated increments the folder counter.
func (c *Collector) FolderCreated() {
	c.FoldersTotal.Inc()
}

// FolderDeleted decrements the folder counter.
func (c *Collector) FolderDeleted() {
	c.FoldersTotal.Dec()
}

// --- Secret version helpers ---

// SecretVersionCreated increments the secret version counter.
func (c *Collector) SecretVersionCreated() {
	c.SecretVersionsTotal.Inc()
}
