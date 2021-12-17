package metrics

import (
	"context"

	"github.com/palantir/go-metrics"
	pkgmetrics "github.com/palantir/pkg/metrics"
)

// ReportMetric: Metrics regarding vulnerabilities.
type ReportMetric interface {
	// Number of vulnerable files found on host.
	VulnerableFilesFound() ReportVulnerableFilesFoundBuilderStage
}

type report struct {
	registry pkgmetrics.Registry
}

func Report(ctx context.Context) ReportMetric {
	return &report{registry: pkgmetrics.FromContext(ctx)}
}

func ReportFromRegistry(registry pkgmetrics.Registry) ReportMetric {
	return &report{registry: registry}
}

type ReportVulnerableFilesFoundBuilderStage interface {
	Gauge() metrics.Gauge
	Unregister()
}

type reportVulnerableFilesFoundBuilder struct {
	registry pkgmetrics.Registry
}

func (b *report) VulnerableFilesFound() ReportVulnerableFilesFoundBuilderStage {
	return &reportVulnerableFilesFoundBuilder{registry: b.registry}
}

func (b *reportVulnerableFilesFoundBuilder) Gauge() metrics.Gauge {
	return b.registry.Gauge("com.palantir.log4j-sniffer.report.vulnerable_files_found")
}

func (b *reportVulnerableFilesFoundBuilder) Unregister() {
	b.registry.Unregister("com.palantir.log4j-sniffer.report.vulnerable_files_found")
}
