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

package cmd

import (
	"context"
	"github.com/palantir/witchcraft-go-logging/wlog"
	"os"

	"github.com/palantir/pkg/signals"
	"github.com/palantir/pkg/uuid"
	wlogtmpl "github.com/palantir/witchcraft-go-logging/wlog-tmpl"
	"github.com/palantir/witchcraft-go-logging/wlog/evtlog/evt2log"
	"github.com/palantir/witchcraft-go-logging/wlog/metriclog/metric1log"
	"github.com/palantir/witchcraft-go-logging/wlog/svclog/svc1log"
	"github.com/palantir/witchcraft-go-logging/wlog/wrappedlog/wrapped1log"
)

// contextWithDefaultLogger creates a context wired up with a multiwriter to write to  standard out
//
// The function returned by contextWithDefaultLogger must be called on application shutdown,
// this will cancel the context and close the file logger.
func contextWithDefaultLogger() (context.Context, func() error) {
	wlog.SetDefaultLoggerProvider(wlogtmpl.LoggerProvider(nil))
	logger := wrapped1log.New(os.Stdout, wlog.InfoLevel, "log4j-sniffer", Version)
	ctx := context.Background()
	ctx = svc1log.WithLogger(ctx, logger.Service(
		svc1log.OriginFromCallLineWithSkip(4),
		svc1log.SafeParam("runID", uuid.NewUUID())))
	ctx = evt2log.WithLogger(ctx, logger.Event())
	ctx = metric1log.WithLogger(ctx, logger.Metric())
	withShutdown, cancel := signals.ContextWithShutdown(ctx)
	return withShutdown, func() error {
		cancel()
		return nil
	}
}
