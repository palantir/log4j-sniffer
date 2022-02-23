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
	"fmt"
	"io"
	"regexp"
	"time"

	"github.com/palantir/log4j-sniffer/pkg/archive"
	"github.com/palantir/log4j-sniffer/pkg/buffer"
	"github.com/palantir/log4j-sniffer/pkg/crawl"
	"github.com/palantir/log4j-sniffer/pkg/log"
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
	ObfuscatedClassNameAverageLength int
	// The maximum average package name length for a jar to be considered obfuscated.
	ObfuscatedPackageNameAverageLength int
	// If true, print out detailed information on each finding as it is found
	PrintDetailedOutput bool
	// Ignores specifies the regular expressions used to determine which directories to omit.
	Ignores []*regexp.Regexp
	// ArchiveOpenMode prescribes the crawler to use either direct-io or standard file opening.
	ArchiveOpenMode archive.FileOpenMode
	// EnableTraceLogging enables trace level logging.
	EnableTraceLogging bool
	// ArchiveDiskSwapMaxSize is the size on disk, in bytes, that is allowed to be used for writing
	// archives over ArchiveMaxSize to disk as temporary files.
	// ArchiveDiskSwapMaxSize is the total size allowed across all files that exist at the same time.
	ArchiveDiskSwapMaxSize uint
	// ArchiveDiskSwapMaxDir is the directory in which temporary files will be written for archives
	// that are over ArchiveMaxSize.
	ArchiveDiskSwapMaxDir string
}

// Crawl crawls identifying and reporting vulnerable files according to crawl.Identify and crawl.Reporter using the
// provided configuration. Returns the number of issues that were found.
func Crawl(ctx context.Context, config Config, process crawl.HandleFindingFunc, stdout, stderr io.Writer) (crawl.Stats, error) {
	var outputWriter io.Writer
	if config.PrintDetailedOutput {
		outputWriter = stdout
	}
	identifier := crawl.Log4jIdentifier{
		Logger: log.Logger{
			ErrorWriter:        stderr,
			EnableTraceLogging: config.EnableTraceLogging,
			OutputWriter:       outputWriter,
		},
		IdentifyObfuscation:                config.ObfuscatedClassNameAverageLength > 0 && config.ObfuscatedPackageNameAverageLength > 0,
		ObfuscatedClassNameAverageLength:   config.ObfuscatedClassNameAverageLength,
		ObfuscatedPackageNameAverageLength: config.ObfuscatedPackageNameAverageLength,
		Limiter:                            limiterFromConfig(config.ArchivesCrawledPerSecond),
		ArchiveWalkTimeout:                 config.ArchiveListTimeout,
		ArchiveMaxDepth:                    config.ArchiveMaxDepth,
		ArchiveWalkers:                     config.archiveWalkers(),
		HandleFinding:                      process,
	}
	crawler := crawl.Crawler{
		Limiter:                     limiterFromConfig(config.DirectoriesCrawledPerSecond),
		ErrorWriter:                 stderr,
		IgnoreDirs:                  config.Ignores,
		DirectoryEntriesPerListCall: 100,
	}

	crawlStats, err := crawler.Crawl(ctx, config.Root, identifier.Identify)
	if err != nil {
		if stderr != nil {
			_, _ = fmt.Fprintf(stderr, "Error crawling: %v\n", err)
		}
		return crawl.Stats{}, err
	}

	return crawlStats, nil
}

func (cfg Config) archiveWalkers() func(string) (archive.WalkerProvider, bool) {
	var converter buffer.ReaderReaderAtConverter
	if cfg.ArchiveDiskSwapMaxSize == 0 {
		// Although using a buffer.InMemoryWithDiskOverflowReaderAtConverter with a max of 0 would yield
		// the same resource limits here, by using a buffer.SizeCappedInMemoryReaderAtConverter we will
		// report more user-friendly error messages when hitting the limits.
		converter = buffer.SizeCappedInMemoryReaderAtConverter(int64(cfg.ArchiveMaxSize))
	} else {
		converter = &buffer.InMemoryWithDiskOverflowReaderAtConverter{
			Path:          cfg.ArchiveDiskSwapMaxDir,
			MaxMemorySize: int64(cfg.ArchiveMaxSize),
			MaxDiskSpace:  int64(cfg.ArchiveDiskSwapMaxSize),
		}
	}
	return archive.Walkers(converter, cfg.ArchiveOpenMode)
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
