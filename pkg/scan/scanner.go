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
)

type Scanner struct {
	Config Config
	crawl.Crawler
	*crawl.Reporter
	crawl.Identifier
}

func NewScannerFromConfig(config Config, outputWriter, errorWriter io.Writer) Scanner {
	return Scanner{
		Config: config,
		Crawler: crawl.Crawler{
			ErrorWriter: errorWriter,
			IgnoreDirs:  config.Ignores,
		},
		Reporter: &crawl.Reporter{
			OutputJSON:      config.OutputJSON,
			OutputWriter:    outputWriter,
			DisableCVE45105: config.DisableCVE45105,
		},
		Identifier: &crawl.Log4jIdentifier{
			ZipWalker:          archive.WalkZipFiles,
			TgzZWalker:         archive.WalkTarGzFiles,
			ArchiveWalkTimeout: config.ArchiveListTimeout,
			OpenFileZipReader:  zip.OpenReader,
			ArchiveMaxDepth:    config.ArchiveMaxDepth,
			ArchiveMaxSize:     config.ArchiveMaxSize,
		},
	}
}
