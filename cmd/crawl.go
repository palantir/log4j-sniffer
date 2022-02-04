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
	"encoding/json"
	"fmt"

	"github.com/fatih/color"
	"github.com/palantir/log4j-sniffer/internal/crawler"
	"github.com/palantir/log4j-sniffer/pkg/crawl"
	"github.com/spf13/cobra"
)

func crawlCmd() *cobra.Command {
	var (
		cmdCrawlFlags             crawlFlags
		cmdCVEFlags               cveFlags
		disableDetailedFindings   bool
		disableFlaggingJndiLookup bool
		disableUnknownVersions    bool
		outputJSON                bool
		outputFilePathOnly        bool
		outputSummary             bool
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
			if outputJSON && outputFilePathOnly {
				return fmt.Errorf("--file-path-only cannot be used with --json")
			}

			reporter := crawl.Reporter{
				OutputJSON:                     outputJSON,
				OutputFilePathOnly:             outputFilePathOnly,
				OutputWriter:                   cmd.OutOrStdout(),
				CVEResolver:                    cmdCVEFlags.cveResolver(),
				DisableFlaggingJndiLookup:      disableFlaggingJndiLookup,
				DisableFlaggingUnknownVersions: disableUnknownVersions,
			}

			crawlConfig, err := createCrawlConfig(args[0], cmdCrawlFlags)
			if err != nil {
				return err
			}
			// only enable printing details if already enabled and we're not in json or file-only mode
			crawlConfig.PrintDetailedOutput = crawlConfig.PrintDetailedOutput && !outputJSON && !outputFilePathOnly

			crawlSum, err := crawler.Crawl(cmd.Context(), crawlConfig, reporter.Report, cmd.OutOrStdout(), cmd.OutOrStderr())
			if err != nil {
				return err
			}

			if outputSummary {
				var output string
				if outputJSON {
					jsonBytes, err := json.Marshal(struct {
						crawl.Stats
						NumImpactedFiles int64 `json:"numImpactedFiles"`
						NumFindings      int64 `json:"findings"`
					}{
						Stats:            crawlSum,
						NumImpactedFiles: reporter.FileCount(),
						NumFindings:      reporter.FindingCount(),
					})
					if err != nil {
						return err
					}
					output = string(jsonBytes)
				} else {
					var cveInfo string
					cveInfo = "CVE-2021-44228 or CVE-2021-45046"
					if !cmdCVEFlags.disableCVE45105 {
						cveInfo += " or CVE-2021-45105"
					}
					if !cmdCVEFlags.disableCVE44832 {
						cveInfo += " or CVE-2021-44832"
					}
					count := reporter.FileCount()
					if count > 0 {
						output = color.RedString("Files affected by %s detected: %d file(s)", cveInfo, count)
					} else {
						output = color.GreenString("No files affected by %s detected", cveInfo)
					}
					output += color.CyanString("\n%d total files scanned, skipped identifying %d files due to config, skipped %d paths due to permission denied errors, encountered %d errors processing paths",
						crawlSum.FilesScanned, crawlSum.PathSkippedCount, crawlSum.PermissionDeniedCount, crawlSum.PathErrorCount)
				}
				_, _ = fmt.Fprintln(cmd.OutOrStdout(), output)
			}
			return err
		},
	}

	applyCrawlFlags(&cmd, &cmdCrawlFlags)
	applyCVEFlags(&cmd, &cmdCVEFlags)
	cmd.Flags().BoolVar(&disableDetailedFindings, "disable-detailed-findings", false, "Do not print out detailed finding information when not outputting in JSON.")
	cmd.Flags().BoolVar(&disableFlaggingJndiLookup, "disable-flagging-jndi-lookup", false, `Do not report results that only match on the presence of a JndiLookup class.
Even when disabled results which match other criteria will still report the presence of JndiLookup if relevant.`)
	cmd.Flags().BoolVar(&disableUnknownVersions, "disable-unknown-versions", false, `Only output issues if the version of log4j can be determined (note that this will cause certain detection mechanisms to be skipped)`)
	cmd.Flags().BoolVar(&outputJSON, "json", false, "If true, output will be in JSON format")
	cmd.Flags().BoolVar(&outputFilePathOnly, "file-path-only", false, "If true, output will consist of only paths to the files in which CVEs are detected")
	cmd.Flags().BoolVar(&outputSummary, "summary", true, "If true, outputs a summary of all operations once program completes")
	return &cmd
}
