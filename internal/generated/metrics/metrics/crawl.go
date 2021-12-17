package metrics

import (
	"context"

	"github.com/palantir/go-metrics"
	pkgmetrics "github.com/palantir/pkg/metrics"
)

// CrawlMetric: Metrics reflecting state of log4j-scanner crawls.
type CrawlMetric interface {
	// Gauge value containing the duration in milliseconds of the most recent crawl.
	DurationMilliseconds() CrawlDurationMillisecondsBuilderStage
	// Value representing status of most recent crawl. Zero for success, non-zero for error.
	Status() CrawlStatusBuilderStage
}

type crawl struct {
	registry pkgmetrics.Registry
}

func Crawl(ctx context.Context) CrawlMetric {
	return &crawl{registry: pkgmetrics.FromContext(ctx)}
}

func CrawlFromRegistry(registry pkgmetrics.Registry) CrawlMetric {
	return &crawl{registry: registry}
}

type CrawlDurationMillisecondsBuilderStage interface {
	Gauge() metrics.Gauge
	Unregister()
}

type crawlDurationMillisecondsBuilder struct {
	registry pkgmetrics.Registry
}

func (b *crawl) DurationMilliseconds() CrawlDurationMillisecondsBuilderStage {
	return &crawlDurationMillisecondsBuilder{registry: b.registry}
}

func (b *crawlDurationMillisecondsBuilder) Gauge() metrics.Gauge {
	return b.registry.Gauge("com.palantir.log4j-scanner.crawl.duration_milliseconds")
}

func (b *crawlDurationMillisecondsBuilder) Unregister() {
	b.registry.Unregister("com.palantir.log4j-scanner.crawl.duration_milliseconds")
}

type CrawlStatusBuilderStage interface {
	Gauge() metrics.Gauge
	Unregister()
}

type crawlStatusBuilder struct {
	registry pkgmetrics.Registry
}

func (b *crawl) Status() CrawlStatusBuilderStage {
	return &crawlStatusBuilder{registry: b.registry}
}

func (b *crawlStatusBuilder) Gauge() metrics.Gauge {
	return b.registry.Gauge("com.palantir.log4j-scanner.crawl.status")
}

func (b *crawlStatusBuilder) Unregister() {
	b.registry.Unregister("com.palantir.log4j-scanner.crawl.status")
}
