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

package scan

import (
	"archive/zip"
	"io"

	"github.com/palantir/log4j-sniffer/pkg/archive"
	"github.com/palantir/log4j-sniffer/pkg/crawl"
	"go.uber.org/ratelimit"
)

type Scanner struct {
	crawl.Crawler
	*crawl.Reporter
	crawl.Identifier
}

func NewScannerFromConfig(config Config, outputWriter, errorWriter io.Writer) Scanner {
	return Scanner{
		Crawler: crawl.Crawler{
			ErrorWriter: errorWriter,
			Limiter:     newRateLimiter(config.DirectoriesCrawledPerSecond),
			IgnoreDirs:  config.Ignores,
		},
		Reporter: &crawl.Reporter{
			OutputJSON:      config.OutputJSON,
			OutputWriter:    outputWriter,
			DisableCVE45105: config.DisableCVE45105,
		},
		Identifier: &crawl.Log4jIdentifier{
			ZipWalker:          archive.WalkZipFiles,
			TarWalker:          archive.WalkTarFiles,
			ArchiveWalkTimeout: config.ArchiveListTimeout,
			Limiter:            newRateLimiter(config.ArchivesCrawledPerSecond),
			OpenFileZipReader:  zip.OpenReader,
			ArchiveMaxDepth:    config.ArchiveMaxDepth,
			ArchiveMaxSize:     config.ArchiveMaxSize,
		},
	}
}

func newRateLimiter(limit int) ratelimit.Limiter {
	if limit > 0 {
		return ratelimit.New(limit)
	}
	return ratelimit.NewUnlimited()
}
