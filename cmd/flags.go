// Copyright (c) 2022 Palantir Technologies. All rights reserved.
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
	"fmt"
	"math"
	"regexp"
	"time"

	"github.com/palantir/log4j-sniffer/internal/crawler"
	"github.com/palantir/log4j-sniffer/pkg/archive"
	"github.com/pkg/errors"
	"github.com/spf13/cobra"
)

type crawlFlags struct {
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
}

func applyCrawlFlags(cmd *cobra.Command, flags *crawlFlags) {
	cmd.Flags().StringSliceVar(&flags.ignoreDirs, "ignore-dir", nil, `Specify directory pattern to ignore. Use multiple times to supply multiple patterns.
Patterns should be relative to the provided root.
e.g. ignore "^/proc" to ignore "/proc" when using a crawl root of "/"`)
	cmd.Flags().StringVar(&flags.archiveOpenMode, "archive-open-mode", "standard", `Supported values:
  standard - standard file opening will be used. This may cause the filesystem cache to be populated with reads from the archive opens.
  directio - direct I/O will be used when opening archives that require sequential reading of their content without being able to skip to file tables at known locations within the file.
             For example, "directio" can have an effect on the way that tar-based archives are read but will have no effect on zip-based archives.
             Using "directio" will cause the filesystem cache to be skipped where possible. "directio" is not supported on tmpfs filesystems and will cause tmpfs archive files to report an error.`)
	cmd.Flags().DurationVar(&flags.perArchiveTimeout, "per-archive-timeout", 15*time.Minute, `If this duration is exceeded when inspecting an archive, 
an error will be logged and the crawler will move onto the next file.`)
	cmd.Flags().UintVar(&flags.nestedArchiveMaxSize, "nested-archive-max-size", 5*1024*1024, `The maximum compressed size in bytes of any nested archive that will be unarchived for inspection.
This limit is made a per-depth level.
The overall limit to nested archive size unarchived should be controlled 
by both the nested-archive-max-size and nested-archive-max-depth.`)
	cmd.Flags().UintVar(&flags.nestedArchiveMaxDepth, "nested-archive-max-depth", 0, `The maximum depth to recurse into nested archives. 
A max depth of 0 will open up an archive on the filesystem but not any nested archives.`)
	cmd.Flags().IntVar(&flags.directoriesCrawledPerSecond, "directories-per-second-rate-limit", 0, `The maximum number of directories to crawl per second. 0 for unlimited.`)
	cmd.Flags().IntVar(&flags.archivesCrawledPerSecond, "archives-per-second-rate-limit", 0, `The maximum number of archives to scan per second. 0 for unlimited.`)
	cmd.Flags().BoolVar(&flags.enableObfuscationDetection, "enable-obfuscation-detection", true, `Enable applying partial bytecode matching to Jars that appear to be obfuscated.`)
	cmd.Flags().BoolVar(&flags.enablePartialMatchingOnAllClasses, "enable-partial-matching-on-all-classes", false, `Enable partial bytecode matching to all class files found.`)
	cmd.Flags().IntVar(&flags.obfuscatedClassNameAverageLength, "maximum-average-obfuscated-class-name-length", 3, `The maximum class name length for a class to be considered obfuscated.`)
	cmd.Flags().IntVar(&flags.obfuscatedPackageNameAverageLength, "maximum-average-obfuscated-package-name-length", 3, `The maximum average package name length a class to be considered obfuscated.`)
	cmd.Flags().BoolVar(&flags.enableTraceLogging, "enable-trace-logging", false, `Enables trace logging whilst crawling. disable-detailed-findings must be set to false (the default value) for this flag to have an effect`)
}

func createCrawlConfig(root string, flags crawlFlags) (crawler.Config, error) {
	ignores, err := flags.resolveIgnoreDirs()
	if err != nil {
		return crawler.Config{}, err
	}

	mode, err := flags.resolveArchiveOpenMode()
	if err != nil {
		return crawler.Config{}, err
	}

	var obfuscatedClassNameAverageLength, obfuscatedPackageNameAverageLength int
	if flags.enableObfuscationDetection {
		obfuscatedClassNameAverageLength = flags.obfuscatedClassNameAverageLength
		obfuscatedPackageNameAverageLength = flags.obfuscatedPackageNameAverageLength
	}
	if flags.enablePartialMatchingOnAllClasses {
		obfuscatedClassNameAverageLength, obfuscatedPackageNameAverageLength = math.MaxInt32, math.MaxInt32
	}

	return crawler.Config{
		Root:                               root,
		ArchiveOpenMode:                    mode,
		ArchiveListTimeout:                 flags.perArchiveTimeout,
		ArchiveMaxDepth:                    flags.nestedArchiveMaxDepth,
		ArchiveMaxSize:                     flags.nestedArchiveMaxSize,
		DirectoriesCrawledPerSecond:        flags.directoriesCrawledPerSecond,
		ArchivesCrawledPerSecond:           flags.archivesCrawledPerSecond,
		ObfuscatedClassNameAverageLength:   obfuscatedClassNameAverageLength,
		ObfuscatedPackageNameAverageLength: obfuscatedPackageNameAverageLength,
		PrintDetailedOutput:                !flags.disableDetailedFindings,
		EnableTraceLogging:                 flags.enableTraceLogging,
		Ignores:                            ignores,
	}, nil
}

func (fs crawlFlags) resolveArchiveOpenMode() (archive.FileOpenMode, error) {
	switch fs.archiveOpenMode {
	case "standard":
		return archive.StandardOpen, nil
	case "directio":
		return archive.DirectIOOpen, nil
	}
	return archive.StandardOpen, fmt.Errorf(`unsupported --archive-open-mode: %s. Supported values are "standard" and "directio"`, fs.archiveOpenMode)
}

func (fs crawlFlags) resolveIgnoreDirs() ([]*regexp.Regexp, error) {
	var ignores []*regexp.Regexp
	for _, pattern := range fs.ignoreDirs {
		compiled, err := regexp.Compile(pattern)
		if err != nil {
			return nil, errors.Wrapf(err, "failed to compile ignore-dir pattern %q", pattern)
		}
		ignores = append(ignores, compiled)
	}
	return ignores, nil
}
