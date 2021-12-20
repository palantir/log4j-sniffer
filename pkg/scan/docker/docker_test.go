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

package docker

import (
	"archive/zip"
	"context"
	"io"
	"testing"

	"github.com/docker/docker/api/types"
	"github.com/palantir/log4j-sniffer/pkg/archive"
	"github.com/palantir/log4j-sniffer/pkg/crawl"
	"github.com/palantir/log4j-sniffer/pkg/scan"
	"github.com/stretchr/testify/assert"
)

func TestScanner_ScanImages(t *testing.T) {
	t.Run("returns non-nil, finds matches in image", func(t *testing.T) {
		scanner := Scanner{
			config: scan.Config{},
			crawler: crawl.Crawler{
				ErrorWriter: io.Discard,
			},
			reporter: &crawl.Reporter{
				OutputWriter: io.Discard,
			},
			identifier: &crawl.Log4jIdentifier{
				ZipWalker:         archive.WalkZipFiles,
				TgzZWalker:        archive.WalkTarGzFiles,
				OpenFileZipReader: zip.OpenReader,
			},
			client: &mockDockerClient{
				imageFile: "../../../examples/docker/log4j.tar",
				imageSummary: types.ImageSummary{
					ID:       "image-w-log4j",
					RepoTags: []string{"bad"},
				},
			},
		}
		count, err := scanner.ScanImages(context.Background())
		assert.NoError(t, err)
		assert.Equal(t, int64(2), count)
	})
}
