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
	"math"
	"regexp"
	"time"

	"github.com/fatih/color"
	"github.com/palantir/log4j-sniffer/internal/crawler"
	"github.com/palantir/log4j-sniffer/pkg/archive"
	"github.com/palantir/log4j-sniffer/pkg/crawl"
	"github.com/pkg/errors"
	"github.com/spf13/cobra"
)

func crawlCmd() *cobra.Command {
	var (
		ignoreDirs                         []string
		archiveOpenMode                    string
		perArchiveTimeout                  time.Duration
		nestedArchiveMaxDepth              uint
		nestedArchiveMaxSize               uint
		directoriesCrawledPerSecond        int
		archivesCrawledPerSecond           int
		enableObfuscationDetection         bool
		obfuscatedClassNameAverageLength   int
		obfuscatedPackageNameAverageLength int
		enablePartialMatchingOnAllClasses  bool
		enableTraceLogging                 bool
		disableDetailedFindings            bool
		disableCVE45105                    bool
		disableCVE44832                    bool
		disableFlaggingJndiLookup          bool
		disableUnknownVersions             bool
		outputJSON                         bool
		outputFilePathOnly                 bool
		outputSummary                      bool
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

			if !enableObfuscationDetection {
				obfuscatedClassNameAverageLength, obfuscatedPackageNameAverageLength = 0, 0
			}
			if enablePartialMatchingOnAllClasses {
				obfuscatedClassNameAverageLength, obfuscatedPackageNameAverageLength = math.MaxInt32, math.MaxInt32
			}

			if outputJSON && outputFilePathOnly {
				return fmt.Errorf("--file-path-only cannot be used with --json")
			}

			var mode archive.FileOpenMode
			switch archiveOpenMode {
			case "standard":
				mode = archive.StandardOpen
			case "directio":
				mode = archive.DirectIOOpen
			default:
				return fmt.Errorf(`unsupported --archive-open-mode: %s. Supported values are "standard" and "directio"`, archiveOpenMode)
			}

			reporter := crawl.Reporter{
				OutputJSON:                     outputJSON,
				OutputFilePathOnly:             outputFilePathOnly,
				OutputWriter:                   cmd.OutOrStdout(),
				DisableCVE45105:                disableCVE45105,
				DisableCVE44832:                disableCVE44832,
				DisableFlaggingJndiLookup:      disableFlaggingJndiLookup,
				DisableFlaggingUnknownVersions: disableUnknownVersions,
			}

			crawlSum, err := crawler.Crawl(cmd.Context(), crawler.Config{
				Root:                               args[0],
				ArchiveOpenMode:                    mode,
				ArchiveListTimeout:                 perArchiveTimeout,
				ArchiveMaxDepth:                    nestedArchiveMaxDepth,
				ArchiveMaxSize:                     nestedArchiveMaxSize,
				DirectoriesCrawledPerSecond:        directoriesCrawledPerSecond,
				ArchivesCrawledPerSecond:           archivesCrawledPerSecond,
				ObfuscatedClassNameAverageLength:   obfuscatedClassNameAverageLength,
				ObfuscatedPackageNameAverageLength: obfuscatedPackageNameAverageLength,
				PrintDetailedOutput:                !disableDetailedFindings && !outputJSON && !outputFilePathOnly,
				EnableTraceLogging:                 enableTraceLogging,
				Ignores:                            ignores,
			}, reporter.Collect, cmd.OutOrStdout(), cmd.OutOrStderr())
			if err != nil {
				return err
			}

			if outputSummary {
				var output string
				if outputJSON {
					jsonBytes, err := json.Marshal(struct {
						crawl.Stats
						NumImpactedFiles int64 `json:"numImpactedFiles"`
					}{
						Stats:            crawlSum,
						NumImpactedFiles: reporter.Count(),
					})
					if err != nil {
						return err
					}
					output = string(jsonBytes)
				} else {
					var cveInfo string
					cveInfo = "CVE-2021-44228 or CVE-2021-45046"
					if !disableCVE45105 {
						cveInfo += " or CVE-2021-45105"
					}
					if !disableCVE44832 {
						cveInfo += " or CVE-2021-44832"
					}
					count := reporter.Count()
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
	cmd.Flags().StringSliceVar(&ignoreDirs, "ignore-dir", nil, `Specify directory pattern to ignore. Use multiple times to supply multiple patterns.
Patterns should be relative to the provided root.
e.g. ignore "^/proc" to ignore "/proc" when using a crawl root of "/"`)
	cmd.Flags().StringVar(&archiveOpenMode, "archive-open-mode", "standard", `Supported values:
  standard - standard file opening will be used. This may cause the filesystem cache to be populated with reads from the archive opens.
  directio - direct I/O will be used when opening archives that require sequential reading of their content without being able to skip to file tables at known locations within the file.
             For example, "directio" can have an effect on the way that tar-based archives are read but will have no effect on zip-based archives.
             Using "directio" will cause the filesystem cache to be skipped where possible. "directio" is not supported on tmpfs filesystems and will cause tmpfs archive files to report an error.`)
	cmd.Flags().DurationVar(&perArchiveTimeout, "per-archive-timeout", 15*time.Minute, `If this duration is exceeded when inspecting an archive, 
an error will be logged and the crawler will move onto the next file.`)
	cmd.Flags().UintVar(&nestedArchiveMaxSize, "nested-archive-max-size", 5*1024*1024, `The maximum compressed size in bytes of any nested archive that will be unarchived for inspection.
This limit is made a per-depth level.
The overall limit to nested archive size unarchived should be controlled 
by both the nested-archive-max-size and nested-archive-max-depth.`)
	cmd.Flags().UintVar(&nestedArchiveMaxDepth, "nested-archive-max-depth", 0, `The maximum depth to recurse into nested archives. 
A max depth of 0 will open up an archive on the filesystem but not any nested archives.`)
	cmd.Flags().IntVar(&directoriesCrawledPerSecond, "directories-per-second-rate-limit", 0, `The maximum number of directories to crawl per second. 0 for unlimited.`)
	cmd.Flags().IntVar(&archivesCrawledPerSecond, "archives-per-second-rate-limit", 0, `The maximum number of archives to scan per second. 0 for unlimited.`)
	cmd.Flags().BoolVar(&enableObfuscationDetection, "enable-obfuscation-detection", true, `Enable applying partial bytecode matching to Jars that appear to be obfuscated.`)
	cmd.Flags().BoolVar(&enablePartialMatchingOnAllClasses, "enable-partial-matching-on-all-classes", false, `Enable partial bytecode matching to all class files found.`)
	cmd.Flags().IntVar(&obfuscatedClassNameAverageLength, "maximum-average-obfuscated-class-name-length", 3, `The maximum class name length for a class to be considered obfuscated.`)
	cmd.Flags().IntVar(&obfuscatedPackageNameAverageLength, "maximum-average-obfuscated-package-name-length", 3, `The maximum average package name length a class to be considered obfuscated.`)
	cmd.Flags().BoolVar(&enableTraceLogging, "enable-trace-logging", false, `Enables trace logging whilst crawling. disable-detailed-findings must be set to false (the default value) for this flag to have an effect`)
	cmd.Flags().BoolVar(&disableDetailedFindings, "disable-detailed-findings", false, "Do not print out detailed finding information when not outputting in JSON.")
	cmd.Flags().BoolVar(&disableFlaggingJndiLookup, "disable-flagging-jndi-lookup", false, `Do not report results that only match on the presence of a JndiLookup class.
Even when disabled results which match other criteria will still report the presence of JndiLookup if relevant.`)
	cmd.Flags().BoolVar(&disableCVE45105, "disable-cve-2021-45105-detection", false, `Disable detection of CVE-2021-45105 in versions up to 2.16.0`)
	cmd.Flags().BoolVar(&disableCVE44832, "disable-cve-2021-44832-detection", false, `Disable detection of CVE-2021-44832 in versions up to 2.17.0`)
	cmd.Flags().BoolVar(&disableUnknownVersions, "disable-unknown-versions", false, `Only output issues if the version of log4j can be determined (note that this will cause certain detection mechanisms to be skipped)`)
	cmd.Flags().BoolVar(&outputJSON, "json", false, "If true, output will be in JSON format")
	cmd.Flags().BoolVar(&outputFilePathOnly, "file-path-only", false, "If true, output will consist of only paths to the files in which CVEs are detected")
	cmd.Flags().BoolVar(&outputSummary, "summary", true, "If true, outputs a summary of all operations once program completes")
	return &cmd
}
