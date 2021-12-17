// Copyright (c) 2018 Palantir Technologies. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package metrics

import (
	"context"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/palantir/go-metrics"
)

var (
	goRuntimeMetricsToExclude = map[string]struct{}{
		"go.runtime.MemStats.BuckHashSys":  {},
		"go.runtime.MemStats.DebugGC":      {},
		"go.runtime.MemStats.EnableGC":     {},
		"go.runtime.MemStats.NextGC":       {},
		"go.runtime.MemStats.LastGC":       {},
		"go.runtime.MemStats.Lookups":      {},
		"go.runtime.MemStats.TotalAlloc":   {}, // TotalAlloc increases as heap objects are allocated, but unlike Alloc and HeapAlloc, it does not decrease when objects are freed
		"go.runtime.MemStats.MCacheInuse":  {},
		"go.runtime.MemStats.MCacheSys":    {},
		"go.runtime.MemStats.MSpanInuse":   {},
		"go.runtime.MemStats.MSpanSys":     {},
		"go.runtime.MemStats.Sys":          {},
		"go.runtime.MemStats.Frees":        {},
		"go.runtime.MemStats.Mallocs":      {},
		"go.runtime.MemStats.StackSys":     {},
		"go.runtime.NumCgoCall":            {},
		"go.runtime.MemStats.PauseTotalNs": {},
	}

	_ Registry = &NoopRegistry{}
	_ Registry = &rootRegistry{}
	_ Registry = &childRegistry{}
)

// RootRegistry is the root metric registry for a product. A root registry has a prefix and a product name.
//
// Built-in Go metrics will be outputted as "<root-prefix>.<key>: <value>".
// Metrics registered on the root registry will be outputted as "<root-prefix>.<NAME>:<key>00: <value>".
// Metrics registered on subregistries of the root will be outputted as "<root-prefix>.<NAME>:<prefix>.<key>: <value>".
type RootRegistry interface {
	Registry

	// Subregistry returns a new subregistry of the root registry on which metrics can be registered.
	//
	// Specified tags will be always included in metrics emitted by a subregistry.
	// Deprecated: Use metrics.FromContext(ctx) instead to get a child registry with tags. Using subregistries and metric names
	// to namespace metrics is discouraged; metric tags should handle this instead.
	Subregistry(prefix string, tags ...Tag) Registry
}

// MetricVisitor is a callback function type that can be passed into Registry.Each to report
// metrics into systems which consume metrics. An example use case is a MetricVisitor which
// writes its argument into a log file.
type MetricVisitor func(name string, tags Tags, value MetricVal)

const (
	defaultReservoirSize = 1028
	defaultAlpha         = 0.015
)

type Registry interface {
	Counter(name string, tags ...Tag) metrics.Counter
	Gauge(name string, tags ...Tag) metrics.Gauge
	GaugeFloat64(name string, tags ...Tag) metrics.GaugeFloat64
	Meter(name string, tags ...Tag) metrics.Meter
	Timer(name string, tags ...Tag) metrics.Timer
	Histogram(name string, tags ...Tag) metrics.Histogram
	HistogramWithSample(name string, sample metrics.Sample, tags ...Tag) metrics.Histogram
	// Each invokes the provided callback function on every user-defined metric registered on the router (including
	// those registered by sub-registries). Each is invoked on each metric in sorted order of the key.
	Each(MetricVisitor)
	// Unregister the metric with the given name and tags.
	Unregister(name string, tags ...Tag)
}

type metricsRegistryProvider interface {
	Registry() metrics.Registry
}

// NewRootMetricsRegistry creates a new root registry for metrics.
func NewRootMetricsRegistry() RootRegistry {
	return &rootRegistry{
		registry:           metrics.NewRegistry(),
		idToMetricWithTags: make(map[metricTagsID]metricWithTags),
	}
}

var runtimeMemStats sync.Once

// CaptureRuntimeMemStats registers runtime memory metrics collectors and spawns
// a goroutine which collects them every collectionFreq. This function can only be called once per lifetime of the
// process and only records metrics if the provided RootRegistry is a *rootRegistry.
//
// Deprecated: use CaptureRuntimeMemStatsWithCancel instead. CaptureRuntimeMemStatsWithCancel has the following
// advantages over this function:
//   * Does not make assumptions about the concrete struct implementing of RootRegistry
//   * Does not restrict the function to being called only once globally
//   * Supports cancellation using a provided context
//   * Can tell if provided RootRegistry does not support Go runtime metric collection based on return value
func CaptureRuntimeMemStats(registry RootRegistry, collectionFreq time.Duration) {
	runtimeMemStats.Do(func() {
		if reg, ok := registry.(*rootRegistry); ok {
			goRegistry := metrics.NewPrefixedChildRegistry(reg.registry, "go.")
			metrics.RegisterRuntimeMemStats(goRegistry)
			go metrics.CaptureRuntimeMemStats(goRegistry, collectionFreq)
		}
	})
}

// CaptureRuntimeMemStatsWithContext creates a child registry of the provided registry that tracks Go runtime memory
// metrics and starts a goroutine that captures them to that registry every collectionFreq. This function only supports
// RootRegistry implementations that implement the metricsRegistryProvider interface -- if the provided RootRegistry
// does not satisfy this interface, this function is a no-op. This function returns true if it starts the runtime metric
// collection goroutine, false otherwise. If this function starts a goroutine, the goroutine runs until the provided
// context is done.
//
// The gauges/metrics etc. used to track runtime statistics are shared globally and the values are reset every time this
// function is called (if it is not a no-op). Note that this function should typically only be called once per Go
// runtime, but no enforcement of this is performed.
func CaptureRuntimeMemStatsWithContext(ctx context.Context, registry RootRegistry, collectionFreq time.Duration) bool {
	mRegProvider, ok := registry.(metricsRegistryProvider)
	if !ok {
		return false
	}

	goRegistry := metrics.NewPrefixedChildRegistry(mRegProvider.Registry(), "go.")
	metrics.RegisterRuntimeMemStats(goRegistry)
	go func() {
		ticker := time.NewTicker(collectionFreq)
		defer ticker.Stop()
		for {
			select {
			case <-ticker.C:
				metrics.CaptureRuntimeMemStatsOnce(goRegistry)
			case <-ctx.Done():
				return
			}
		}
	}()
	return true
}

type rootRegistry struct {
	// the actual metrics.Registry on which all metrics are installed.
	registry metrics.Registry

	// map from metricTagsID to metricWithTags for all of the metrics in the userDefinedMetricsRegistry.
	idToMetricWithTags map[metricTagsID]metricWithTags

	// mutex lock to protect metric map concurrent writes
	idToMetricMutex sync.RWMutex
}

type childRegistry struct {
	prefix string
	tags   Tags
	root   *rootRegistry
}

// NoopRegistry is a "lightweight, high-speed implementation of Registry for when simplicity and performance
// matter above all else".
//
// Useful in testing infrastructure. Doesn't collect, store, or emit any metrics.
type NoopRegistry struct{}

func (r NoopRegistry) Counter(_ string, _ ...Tag) metrics.Counter {
	return metrics.NilCounter{}
}

func (r NoopRegistry) Gauge(_ string, _ ...Tag) metrics.Gauge {
	return metrics.NilGauge{}
}

func (r NoopRegistry) GaugeFloat64(_ string, _ ...Tag) metrics.GaugeFloat64 {
	return metrics.NilGaugeFloat64{}
}

func (r NoopRegistry) Meter(_ string, _ ...Tag) metrics.Meter {
	return metrics.NilMeter{}
}

func (r NoopRegistry) Timer(_ string, _ ...Tag) metrics.Timer {
	return metrics.NilTimer{}
}

func (r NoopRegistry) Histogram(_ string, _ ...Tag) metrics.Histogram {
	return metrics.NilHistogram{}
}

func (r NoopRegistry) HistogramWithSample(_ string, _ metrics.Sample, _ ...Tag) metrics.Histogram {
	return metrics.NilHistogram{}
}

func (r NoopRegistry) Each(MetricVisitor) {
	// no-op
}

func (r NoopRegistry) Unregister(name string, tags ...Tag) {
	// no-op
}

func (r *childRegistry) Counter(name string, tags ...Tag) metrics.Counter {
	return r.root.Counter(r.prefix+name, append(r.tags, tags...)...)
}

func (r *childRegistry) Gauge(name string, tags ...Tag) metrics.Gauge {
	return r.root.Gauge(r.prefix+name, append(r.tags, tags...)...)
}

func (r *childRegistry) GaugeFloat64(name string, tags ...Tag) metrics.GaugeFloat64 {
	return r.root.GaugeFloat64(r.prefix+name, append(r.tags, tags...)...)
}

func (r *childRegistry) Meter(name string, tags ...Tag) metrics.Meter {
	return r.root.Meter(r.prefix+name, append(r.tags, tags...)...)
}

func (r *childRegistry) Timer(name string, tags ...Tag) metrics.Timer {
	return r.root.Timer(r.prefix+name, append(r.tags, tags...)...)
}

func (r *childRegistry) Histogram(name string, tags ...Tag) metrics.Histogram {
	return r.root.Histogram(r.prefix+name, append(r.tags, tags...)...)
}

func (r *childRegistry) HistogramWithSample(name string, sample metrics.Sample, tags ...Tag) metrics.Histogram {
	return r.root.HistogramWithSample(r.prefix+name, sample, append(r.tags, tags...)...)
}

func (r *childRegistry) Each(f MetricVisitor) {
	r.root.Each(func(name string, tags Tags, metric MetricVal) {
		name = strings.TrimPrefix(name, r.prefix)
		f(name, tags, metric)
	})
}

func (r *childRegistry) Unregister(name string, tags ...Tag) {
	r.root.Unregister(r.prefix+name, append(r.tags, tags...)...)
}

func (r *rootRegistry) Subregistry(prefix string, tags ...Tag) Registry {
	if prefix != "" && !strings.HasSuffix(prefix, ".") {
		prefix = prefix + "."
	}
	return &childRegistry{
		prefix: prefix,
		tags:   Tags(tags),
		root:   r,
	}
}

func (r *rootRegistry) Each(f MetricVisitor) {
	// sort names so that iteration order is consistent
	var sortedMetricIDs []string
	allMetrics := make(map[string]interface{})
	r.registry.Each(func(name string, metric interface{}) {
		// filter out the runtime metrics that are defined in the exclude list
		if _, ok := goRuntimeMetricsToExclude[name]; ok {
			return
		}
		sortedMetricIDs = append(sortedMetricIDs, name)
		allMetrics[name] = metric
	})
	sort.Strings(sortedMetricIDs)

	for _, id := range sortedMetricIDs {
		r.idToMetricMutex.RLock()
		metricWithTags, ok := r.idToMetricWithTags[metricTagsID(id)]
		r.idToMetricMutex.RUnlock()

		var name string
		var tags Tags
		if ok {
			name = metricWithTags.name
			tags = make(Tags, len(metricWithTags.tags))
			copy(tags, metricWithTags.tags)
		} else if r.registry.Get(id) != nil {
			// Metric was added to rcrowley registry outside of our registry.
			// This is likely a go runtime metric (nothing else is exposed).
			name = id
		} else {
			// Metric was unregistered between us looking at the registry and idToMetricWithTags, move on
			continue
		}

		val := ToMetricVal(allMetrics[id])
		if val == nil {
			// this should never happen as all the things we put inside the registry can be turned into MetricVal
			panic("could not convert metric to MetricVal")
		}
		f(name, tags, val)
	}
}

func (r *rootRegistry) Unregister(name string, tags ...Tag) {
	metricID := toMetricTagsID(name, newSortedTags(tags))
	r.registry.Unregister(string(metricID))

	// This must happen after the registry Unregister() above to preserve the correctness guarantees in Each()
	r.idToMetricMutex.Lock()
	delete(r.idToMetricWithTags, metricID)
	r.idToMetricMutex.Unlock()
}

func (r *rootRegistry) Counter(name string, tags ...Tag) metrics.Counter {
	return metrics.GetOrRegisterCounter(r.registerMetric(name, tags), r.registry)
}

func (r *rootRegistry) Gauge(name string, tags ...Tag) metrics.Gauge {
	return metrics.GetOrRegisterGauge(r.registerMetric(name, tags), r.registry)
}

func (r *rootRegistry) GaugeFloat64(name string, tags ...Tag) metrics.GaugeFloat64 {
	return metrics.GetOrRegisterGaugeFloat64(r.registerMetric(name, tags), r.registry)
}

func (r *rootRegistry) Meter(name string, tags ...Tag) metrics.Meter {
	return metrics.GetOrRegisterMeter(r.registerMetric(name, tags), r.registry)
}

func (r *rootRegistry) Timer(name string, tags ...Tag) metrics.Timer {
	return getOrRegisterMicroSecondsTimer(r.registerMetric(name, tags), r.registry)
}

func (r *rootRegistry) Histogram(name string, tags ...Tag) metrics.Histogram {
	return r.HistogramWithSample(name, DefaultSample(), tags...)
}

func (r *rootRegistry) HistogramWithSample(name string, sample metrics.Sample, tags ...Tag) metrics.Histogram {
	return metrics.GetOrRegisterHistogram(r.registerMetric(name, tags), r.registry, sample)
}

func (r *rootRegistry) Registry() metrics.Registry {
	return r.registry
}

func DefaultSample() metrics.Sample {
	return metrics.NewExpDecaySample(defaultReservoirSize, defaultAlpha)
}

func (r *rootRegistry) registerMetric(name string, tags Tags) string {
	sortedTags := newSortedTags(tags)
	metricID := toMetricTagsID(name, sortedTags)
	r.idToMetricMutex.Lock()
	r.idToMetricWithTags[metricID] = metricWithTags{
		name: name,
		tags: sortedTags,
	}
	r.idToMetricMutex.Unlock()
	return string(metricID)
}

// metricWithTags stores a specific metric with its set of tags.
type metricWithTags struct {
	name string
	tags Tags
}

// metricTagsID is the unique identifier for a given metric. Each {metricName, set<Tag>} pair is considered to be a
// unique metric. A metricTagsID is a string of the following form: "<name>|<tag1>|<tag2>". The tags appear in
// ascending alphanumeric order. If a metric does not have any tags, its metricsTagsID is of the form: "<name>".
type metricTagsID string

// toMetricTagsID generates the metricTagsID identifier for the metricWithTags. A unique {metricName, set<Tag>} input will
// generate a unique output. This implementation tries to minimize memory allocation and runtime.
// The ID is created by adding the tags in the order they are provided (this means that, if the caller wants a specific set of tags to always
// result in the same ID, they must sort the Tags before providing them to this function).
func toMetricTagsID(name string, tags Tags) metricTagsID {
	// calculate how large to make our byte buffer below
	bufSize := len(name)
	for _, t := range tags {
		bufSize += len(t.keyValue) + 1 // 1 for separator
	}
	buf := strings.Builder{}
	buf.Grow(bufSize)
	_, _ = buf.WriteString(name)
	for _, tag := range tags {
		_, _ = buf.WriteRune('|')
		_, _ = buf.WriteString(tag.keyValue)
	}
	return metricTagsID(buf.String())
}

// newSortedTags copies the tag slice before sorting so that in-place mutation does not affect the input slice.
func newSortedTags(tags Tags) Tags {
	tagsCopy := append(tags[:0:0], tags...)
	sort.Sort(tagsCopy)
	return tagsCopy
}
