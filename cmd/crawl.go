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

	"github.com/palantir/log4j-sniffer/internal/crawler"
	"github.com/pkg/errors"
	"github.com/spf13/cobra"
)

func crawlCmd() *cobra.Command {
	var (
		ignoreDirs        []string
		perArchiveTimeout time.Duration
		archiveMaxDepth   uint
		disableCVE45105   bool
		outputJSON        bool
		outputSummary     bool
	)

	cmd := cobra.Command{
		Use:   "crawl <root>",
		Args:  cobra.ExactArgs(1),
		Short: "Crawl filesystem to scan for jars vulnerable to CVE-2021-45046.",
		Long: `Crawl filesystem to scan for jars vulnerable to CVE-2021-45046.
Root must be provided and can be a single file or directory.
If a directory is provided, it is traversed and all files are scanned.
Use the ignore-dir flag to provide directories of which to ignore all nested files.
`,
		RunE: func(cmd *cobra.Command, args []string) error {
			var ignores []*regexp.Regexp
			for _, pattern := range ignoreDirs {
				compiled, err := regexp.Compile(pattern)
				if err != nil {
					return errors.Wrapf(err, "failed to compile ignore-dir pattern %q", pattern)
				}
				ignores = append(ignores, compiled)
			}

			_, err := crawler.Crawl(cmd.Context(), crawler.Config{
				Root:               args[0],
				ArchiveListTimeout: perArchiveTimeout,
				ArchiveMaxDepth:    archiveMaxDepth,
				DisableCVE45105:    disableCVE45105,
				Ignores:            ignores,
				OutputJSON:         outputJSON,
				OutputSummary:      outputSummary,
			}, cmd.OutOrStdout(), cmd.OutOrStderr())
			return err
		},
	}
	cmd.Flags().StringSliceVar(&ignoreDirs, "ignore-dir", nil, `Specify directory pattern to ignore. Use multiple times to supply multiple patterns.
Patterns should be relative to the provided root.
e.g. ignore "^/proc" to ignore "/proc" when using a crawl root of "/"`)
	cmd.Flags().DurationVar(&perArchiveTimeout, "per-archive-timeout", 15*time.Minute, `If this duration is exceeded when inspecting an archive, an error will be logged and the crawler will move onto the next file.`)
	cmd.Flags().UintVar(&archiveMaxDepth, "archive-max-depth", 0, `The maximum depth to recurse into nested archives. A max depth of 0 will open up an archive on the filesystem but not any nested archives.`)
	cmd.Flags().BoolVar(&disableCVE45105, "disable-cve-2021-45105-detection", false, `Disable detection of CVE-2021-45105 in versions up to 2.16.0`)
	cmd.Flags().BoolVar(&outputJSON, "json", false, "If true, output will be in JSON format")
	cmd.Flags().BoolVar(&outputSummary, "summary", true, "If true, outputs a summary of all operations once program completes")
	return &cmd
}
