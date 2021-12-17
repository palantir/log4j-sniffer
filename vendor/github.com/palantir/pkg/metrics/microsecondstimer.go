// Copyright (c) 2019 Palantir Technologies. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package metrics

import (
	"sync"
	"time"

	"github.com/palantir/go-metrics"
)

// getOrRegisterMicroSecondsTimer returns an existing Timer or constructs and registers a new microSecondsTimer.
// Be sure to unregister the meter from the registry once it is of no use to allow for garbage collection.
// Based on metrics.GetOrRegisterTimer.
func getOrRegisterMicroSecondsTimer(name string, r metrics.Registry) metrics.Timer {
	if nil == r {
		r = metrics.DefaultRegistry
	}
	return r.GetOrRegister(name, newMicroSecondsTimer).(metrics.Timer)
}

// newMicroSecondsTimer creates a new microSecondsTimer. It is based on metrics.NewTimer.
func newMicroSecondsTimer() metrics.Timer {
	if metrics.UseNilMetrics {
		return metrics.NilTimer{}
	}
	return &microSecondsTimer{
		histogram: metrics.NewHistogram(metrics.NewExpDecaySample(1028, 0.015)),
		meter:     metrics.NewMeter(),
	}
}

// microSecondsTimer is a timer that records its metrics in microseconds (as opposed to the regular metrics.Timer,
// which records its units in nanoseconds). It is based on metrics.StandardTimer.
type microSecondsTimer struct {
	histogram metrics.Histogram
	meter     metrics.Meter
	mutex     sync.Mutex
}

// Count returns the number of events recorded.
func (t *microSecondsTimer) Count() int64 {
	return t.histogram.Count()
}

// Max returns the maximum value in the sample.
func (t *microSecondsTimer) Max() int64 {
	return t.histogram.Max()
}

// Mean returns the mean of the values in the sample.
func (t *microSecondsTimer) Mean() float64 {
	return t.histogram.Mean()
}

// Min returns the minimum value in the sample.
func (t *microSecondsTimer) Min() int64 {
	return t.histogram.Min()
}

// Percentile returns an arbitrary percentile of the values in the sample.
func (t *microSecondsTimer) Percentile(p float64) float64 {
	return t.histogram.Percentile(p)
}

// Percentiles returns a slice of arbitrary percentiles of the values in the
// sample.
func (t *microSecondsTimer) Percentiles(ps []float64) []float64 {
	return t.histogram.Percentiles(ps)
}

// Rate1 returns the one-minute moving average rate of events per second.
func (t *microSecondsTimer) Rate1() float64 {
	return t.meter.Rate1()
}

// Rate5 returns the five-minute moving average rate of events per second.
func (t *microSecondsTimer) Rate5() float64 {
	return t.meter.Rate5()
}

// Rate15 returns the fifteen-minute moving average rate of events per second.
func (t *microSecondsTimer) Rate15() float64 {
	return t.meter.Rate15()
}

// RateMean returns the meter's mean rate of events per second.
func (t *microSecondsTimer) RateMean() float64 {
	return t.meter.RateMean()
}

// Snapshot returns a read-only copy of the timer.
func (t *microSecondsTimer) Snapshot() metrics.Timer {
	t.mutex.Lock()
	defer t.mutex.Unlock()
	return &timerSnapshot{
		histogram: t.histogram.Snapshot().(*metrics.HistogramSnapshot),
		meter:     t.meter.Snapshot().(*metrics.MeterSnapshot),
	}
}

// StdDev returns the standard deviation of the values in the sample.
func (t *microSecondsTimer) StdDev() float64 {
	return t.histogram.StdDev()
}

// Stop stops the meter.
func (t *microSecondsTimer) Stop() {
	t.meter.Stop()
}

// Sum returns the sum in the sample.
func (t *microSecondsTimer) Sum() int64 {
	return t.histogram.Sum()
}

// Record the duration of the execution of the given function.
func (t *microSecondsTimer) Time(f func()) {
	ts := time.Now()
	f()
	t.Update(time.Since(ts))
}

// Record the duration of an event.
func (t *microSecondsTimer) Update(d time.Duration) {
	t.mutex.Lock()
	defer t.mutex.Unlock()
	t.histogram.Update(int64(d / time.Microsecond))
	t.meter.Mark(1)
}

// Record the duration of an event that started at a time and ends now.
func (t *microSecondsTimer) UpdateSince(ts time.Time) {
	t.mutex.Lock()
	defer t.mutex.Unlock()
	t.histogram.Update(int64(time.Since(ts) / time.Microsecond))
	t.meter.Mark(1)
}

// Variance returns the variance of the values in the sample.
func (t *microSecondsTimer) Variance() float64 {
	return t.histogram.Variance()
}

// timerSnapshot is a read-only copy of another Timer. Based on metrics.TimerSnapshot.
type timerSnapshot struct {
	histogram *metrics.HistogramSnapshot
	meter     *metrics.MeterSnapshot
}

// Count returns the number of events recorded at the time the snapshot was
// taken.
func (t *timerSnapshot) Count() int64 { return t.histogram.Count() }

// Max returns the maximum value at the time the snapshot was taken.
func (t *timerSnapshot) Max() int64 { return t.histogram.Max() }

// Mean returns the mean value at the time the snapshot was taken.
func (t *timerSnapshot) Mean() float64 { return t.histogram.Mean() }

// Min returns the minimum value at the time the snapshot was taken.
func (t *timerSnapshot) Min() int64 { return t.histogram.Min() }

// Percentile returns an arbitrary percentile of sampled values at the time the
// snapshot was taken.
func (t *timerSnapshot) Percentile(p float64) float64 {
	return t.histogram.Percentile(p)
}

// Percentiles returns a slice of arbitrary percentiles of sampled values at
// the time the snapshot was taken.
func (t *timerSnapshot) Percentiles(ps []float64) []float64 {
	return t.histogram.Percentiles(ps)
}

// Rate1 returns the one-minute moving average rate of events per second at the
// time the snapshot was taken.
func (t *timerSnapshot) Rate1() float64 { return t.meter.Rate1() }

// Rate5 returns the five-minute moving average rate of events per second at
// the time the snapshot was taken.
func (t *timerSnapshot) Rate5() float64 { return t.meter.Rate5() }

// Rate15 returns the fifteen-minute moving average rate of events per second
// at the time the snapshot was taken.
func (t *timerSnapshot) Rate15() float64 { return t.meter.Rate15() }

// RateMean returns the meter's mean rate of events per second at the time the
// snapshot was taken.
func (t *timerSnapshot) RateMean() float64 { return t.meter.RateMean() }

// Snapshot returns the snapshot.
func (t *timerSnapshot) Snapshot() metrics.Timer { return t }

// StdDev returns the standard deviation of the values at the time the snapshot
// was taken.
func (t *timerSnapshot) StdDev() float64 { return t.histogram.StdDev() }

// Stop is a no-op.
func (t *timerSnapshot) Stop() {}

// Sum returns the sum at the time the snapshot was taken.
func (t *timerSnapshot) Sum() int64 { return t.histogram.Sum() }

// Time panics.
func (*timerSnapshot) Time(func()) {
	panic("Time called on a timerSnapshot")
}

// Update panics.
func (*timerSnapshot) Update(time.Duration) {
	panic("Update called on a timerSnapshot")
}

// UpdateSince panics.
func (*timerSnapshot) UpdateSince(time.Time) {
	panic("UpdateSince called on a timerSnapshot")
}

// Variance returns the variance of the values at the time the snapshot was
// taken.
func (t *timerSnapshot) Variance() float64 { return t.histogram.Variance() }
