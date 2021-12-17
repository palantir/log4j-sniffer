// Copyright (c) 2021 Palantir Technologies. All rights reserved.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package crawler

import (
	"testing"
	"time"

	"github.com/palantir/log4j-sniffer/internal/generated/metrics/metrics"
	"github.com/palantir/log4j-sniffer/pkg/testcontext"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestCrawl(t *testing.T) {
	t.Run("emits status of 1 on failed crawl", func(t *testing.T) {
		ctx := testcontext.WithCleanMetricsRegistry(t)
		require.Error(t, Crawl(ctx, 10*time.Second, "non-existant-root", nil))
		assert.EqualValues(t, 1, metrics.Crawl(ctx).Status().Gauge().Value())
	})

	t.Run("emits status of 0 on successful crawl", func(t *testing.T) {
		ctx := testcontext.WithCleanMetricsRegistry(t)
		metrics.Crawl(ctx).Status().Gauge().Update(666)
		require.NoError(t, Crawl(ctx, 10*time.Second, t.TempDir(), nil))
		assert.EqualValues(t, 0, metrics.Crawl(ctx).Status().Gauge().Value())
	})
}
