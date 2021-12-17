// Copyright (c) 2018 Palantir Technologies. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package metrics

import (
	"github.com/palantir/go-metrics"
)

type MetricVal interface {
	Type() string
	Values() map[string]interface{}
}

func ToMetricVal(in interface{}) MetricVal {
	switch val := in.(type) {
	case metrics.Counter:
		return &counterVal{Counter: val}
	case metrics.Gauge:
		return &gaugeVal{Gauge: val}
	case metrics.GaugeFloat64:
		return &gaugeFloat64Val{GaugeFloat64: val}
	case metrics.Histogram:
		return &histogramVal{Histogram: val}
	case metrics.Meter:
		return &meterVal{Meter: val}
	case metrics.Timer:
		return &timerVal{Timer: val}
	}
	return nil
}

type counterVal struct {
	metrics.Counter
}

func (v *counterVal) Type() string {
	return "counter"
}

func (v *counterVal) Values() map[string]interface{} {
	return map[string]interface{}{
		"count": v.Count(),
	}
}

type gaugeVal struct {
	metrics.Gauge
}

func (v *gaugeVal) Type() string {
	return "gauge"
}

func (v *gaugeVal) Values() map[string]interface{} {
	return map[string]interface{}{
		"value": v.Value(),
	}
}

type gaugeFloat64Val struct {
	metrics.GaugeFloat64
}

func (v *gaugeFloat64Val) Type() string {
	return "gauge"
}

func (v *gaugeFloat64Val) Values() map[string]interface{} {
	return map[string]interface{}{
		"value": v.Value(),
	}
}

type histogramVal struct {
	metrics.Histogram
}

func (v *histogramVal) Type() string {
	return "histogram"
}

func (v *histogramVal) Values() map[string]interface{} {
	return map[string]interface{}{
		"min":    v.Histogram.Min(),
		"max":    v.Histogram.Max(),
		"mean":   v.Histogram.Mean(),
		"stddev": v.Histogram.StdDev(),
		"p50":    v.Histogram.Percentile(0.5),
		"p95":    v.Histogram.Percentile(0.95),
		"p99":    v.Histogram.Percentile(0.99),
		"count":  v.Histogram.Count(),
	}
}

type meterVal struct {
	metrics.Meter
}

func (v *meterVal) Type() string {
	return "meter"
}

func (v *meterVal) Values() map[string]interface{} {
	return map[string]interface{}{
		"count": v.Meter.Count(),
		"1m":    v.Meter.Rate1(),
		"5m":    v.Meter.Rate5(),
		"15m":   v.Meter.Rate15(),
		"mean":  v.Meter.RateMean(),
	}
}

type timerVal struct {
	metrics.Timer
}

func (v *timerVal) Type() string {
	return "timer"
}

func (v *timerVal) Values() map[string]interface{} {
	return map[string]interface{}{
		"count":    v.Timer.Count(),
		"1m":       v.Timer.Rate1(),
		"5m":       v.Timer.Rate5(),
		"15m":      v.Timer.Rate15(),
		"meanRate": v.Timer.RateMean(),
		"min":      v.Timer.Min(),
		"max":      v.Timer.Max(),
		"mean":     v.Timer.Mean(),
		"stddev":   v.Timer.StdDev(),
		"p50":      v.Timer.Percentile(0.5),
		"p95":      v.Timer.Percentile(0.95),
		"p99":      v.Timer.Percentile(0.99),
	}
}
