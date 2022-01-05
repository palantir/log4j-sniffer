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
	"context"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"regexp"
	"time"

	"github.com/fatih/color"
	"github.com/palantir/log4j-sniffer/pkg/archive"
	"github.com/palantir/log4j-sniffer/pkg/crawl"
	"go.uber.org/ratelimit"
)

type Config struct {
	// Root is the root directory for the crawl operation
	Root string
	// ArchiveListTimeout is the maximum amount of time that will be spent analyzing an archive. Once this duration has
	// passed for a single archive, it is skipped and recorded as such.
	ArchiveListTimeout time.Duration
	// ArchiveMaxDepth is the maximum archive depth to recurse into. A value of 0 will open up an archive on the
	// filesystem but will not recurse into any nested archives within it.
	ArchiveMaxDepth uint
	// ArchiveMaxDepth is the maximum nested archive size that will be unarchived for inspection.
	ArchiveMaxSize uint
	// Maximum number of directories to scan per second, or 0 for no limit.
	DirectoriesCrawledPerSecond int
	// Maximum number of archives to scan per second, or 0 for no limit.
	ArchivesCrawledPerSecond int
	// The maximum average class name length for a jar to be considered obfuscated.
	ObfuscatedClassNameAverageLength uint32
	// The maximum average package name length for a jar to be considered obfuscated.
	ObfuscatedPackageNameAverageLength uint32
	// If true, print out detailed information on each finding as it is found
	PrintDetailedOutput bool
	// If true, doesn't flag on Jars which only contain JndiLookup classes and do not meet any other criteria for Log4j presence.
	DisableFlaggingJndiLookup bool
	// If true, disables detection of CVE-2021-45105
	DisableCVE45105 bool
	// If true, disables detection of CVE-2021-44832
	DisableCVE44832 bool
	// Ignores specifies the regular expressions used to determine which directories to omit.
	Ignores []*regexp.Regexp
	// If true, causes all output to be in JSON format (one JSON object per line).
	OutputJSON bool
	// If true, prints summary output after completion.
	OutputSummary bool
}

type SummaryJSON struct {
	crawl.Stats
	NumImpactedFiles int64 `json:"numImpactedFiles"`
}

// Crawl crawls identifying and reporting vulnerable files according to crawl.Identify and crawl.Reporter using the
// provided configuration. Returns the number of issues that were found.
func Crawl(ctx context.Context, config Config, stdout, stderr io.Writer) (int64, error) {
	var outputWriter io.Writer
	if config.PrintDetailedOutput {
		outputWriter = stdout
	}
	identifier := crawl.Log4jIdentifier{
		ErrorWriter:                        stderr,
		DetailedOutputWriter:               outputWriter,
		IdentifyObfuscation:                config.ObfuscatedClassNameAverageLength > 0 && config.ObfuscatedPackageNameAverageLength > 0,
		ObfuscatedClassNameAverageLength:   float32(config.ObfuscatedClassNameAverageLength),
		ObfuscatedPackageNameAverageLength: float32(config.ObfuscatedPackageNameAverageLength),
		Limiter:                            limiterFromConfig(config.ArchivesCrawledPerSecond),
		ArchiveWalkTimeout:                 config.ArchiveListTimeout,
		ArchiveMaxDepth:                    config.ArchiveMaxDepth,
		ArchiveMaxSize:                     config.ArchiveMaxSize,
		OpenFile:                           os.Open,
		ParseArchiveFormat:                 archive.ParseArchiveFormatFromFile,
		ArchiveWalkers: func(formatType archive.FormatType) (archive.WalkerProvider, bool) {
			switch formatType {
			case archive.ZipArchive:
				return archive.ZipArchiveWalkers(int(config.ArchiveMaxSize)), true
			case archive.TarArchive:
				return archive.TarArchiveWalkers(), true
			case archive.TarGzArchive:
				return archive.TarGzWalkers(), true
			case archive.TarBz2Archive:
				return archive.TarBz2Walkers(), true
			}
			return nil, false
		},
	}
	crawler := crawl.Crawler{
		Limiter:     limiterFromConfig(config.DirectoriesCrawledPerSecond),
		ErrorWriter: stderr,
		IgnoreDirs:  config.Ignores,
	}
	reporter := crawl.Reporter{
		OutputJSON:      config.OutputJSON,
		OutputWriter:    stdout,
		DisableCVE45105: config.DisableCVE45105,
		DisableCVE44832: config.DisableCVE44832,
	}

	crawlStats, err := crawler.Crawl(ctx, config.Root, identifier.Identify, reporter.Collect)
	if err != nil {
		if stderr != nil {
			_, _ = fmt.Fprintf(stderr, "Error crawling: %v\n", err)
		}
		return 0, err
	}

	count := reporter.Count()
	if config.OutputSummary {
		cveInfo := "CVE-2021-44228 or CVE-2021-45046"
		if !config.DisableCVE45105 {
			cveInfo += " or CVE-2021-45105"
		}
		if !config.DisableCVE44832 {
			cveInfo += " or CVE-2021-44832"
		}

		var output string
		if config.OutputJSON {
			jsonBytes, err := json.Marshal(SummaryJSON{
				Stats:            crawlStats,
				NumImpactedFiles: count,
			})
			if err != nil {
				return 0, err
			}
			output = string(jsonBytes)
		} else {
			if count > 0 {
				output = color.RedString("Files affected by %s detected: %d file(s)", cveInfo, count)
			} else {
				output = color.GreenString("No files affected by %s detected", cveInfo)
			}
			output += color.CyanString("\n%d total files scanned, skipped %d paths due to permission denied errors, encountered %d errors processing paths", crawlStats.FilesScanned, crawlStats.PermissionDeniedCount, crawlStats.PathErrorCount)
		}
		_, _ = fmt.Fprintln(stdout, output)
	}
	return count, nil
}

func limiterFromConfig(limit int) ratelimit.Limiter {
	var limiter ratelimit.Limiter
	if limit > 0 {
		limiter = ratelimit.New(limit)
	} else {
		limiter = ratelimit.NewUnlimited()
	}
	return limiter
}
