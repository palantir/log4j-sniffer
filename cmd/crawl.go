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
	"regexp"
	"time"

	"github.com/palantir/log4j-scanner/internal/crawler"
	"github.com/palantir/log4j-scanner/pkg/metrics"
	werror "github.com/palantir/witchcraft-go-error"
	"github.com/palantir/witchcraft-go-logging/wlog/svclog/svc1log"
	"github.com/spf13/cobra"
)

func crawlCmd() *cobra.Command {
	var ignoreDirs []string
	var perArchiveTimeout time.Duration
	cmd := cobra.Command{
		Use:   "crawl <root>",
		Args:  cobra.ExactArgs(1),
		Short: "Crawl filesystem to scan for vulnerable jars.",
		Long: `Crawl filesystem to scan for vulnerable jars.
Root must be provided and can be a single file or directory.
If a directory is provided, it is traversed and all files are scanned.
Use the ignore-dir flag to provide directories of which to ignore all nested files.
`,
		RunE: func(cmd *cobra.Command, args []string) error {
			ctx, closeLogger := contextWithDefaultLogger()
			defer func() {
				metrics.Flush(ctx)
				if err := closeLogger(); err != nil {
					svc1log.FromContext(ctx).Error("Error closing logger",
						svc1log.Stacktrace(err))
				}
			}()
			var ignores []*regexp.Regexp
			for _, pattern := range ignoreDirs {
				compiled, err := regexp.Compile(pattern)
				if err != nil {
					return werror.ErrorWithContextParams(ctx, "Error compile ignore-dir pattern",
						werror.SafeParam("pattern", pattern))
				}
				ignores = append(ignores, compiled)
			}

			return crawler.Crawl(ctx, perArchiveTimeout, args[0], ignores)
		},
	}
	cmd.Flags().StringSliceVar(&ignoreDirs, "ignore-dir", nil, `Specify directory pattern to ignore. Use multiple times to supply multiple patterns.
Patterns should be relative to the provided root.
e.g. ignore "^proc" to ignore "/proc" when using a crawl root of "/"`)
	cmd.Flags().DurationVar(&perArchiveTimeout, "per-archive-timeout", 15*time.Minute, `If this duration is exceeded when inspecting an archive, an error will be logged and the crawler will move onto the next file.`)
	return &cmd
}
