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

package testcontext

import (
	"context"
	"io/ioutil"
	"testing"

	"github.com/palantir/pkg/metrics"
	"github.com/palantir/witchcraft-go-logging/wlog"
	"github.com/palantir/witchcraft-go-logging/wlog/svclog/svc1log"
)

// GetTestContext switches the logger to a discarding logger to avoid distracting logs in test output.
func GetTestContext(tb testing.TB) context.Context {
	return svc1log.WithLogger(context.Background(), svc1log.New(ioutil.Discard, wlog.DebugLevel))
}

func WithCleanMetricsRegistry(tb testing.TB) context.Context {
	// new registry so that there are no side-effects from other test cases
	return metrics.WithRegistry(GetTestContext(tb), metrics.NewRootMetricsRegistry())
}
