// Copyright (c) 2018 Palantir Technologies. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package metrics

import (
	"context"
	"time"
)

// RunEmittingRegistry periodically calls registry.Each with a provided visit function. See the
// documentation for Registry for the arguments of the visit function. RunEmittingRegistry blocks forever
// (or until ctx is cancelled) and should be started in its own goroutine.
func RunEmittingRegistry(ctx context.Context, registry Registry, emitFrequency time.Duration, visitor MetricVisitor) {
	t := time.NewTicker(emitFrequency)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			registry.Each(visitor)
		}
	}
}
