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
	"context"
	"io"
	"testing"

	"github.com/docker/docker/api/types"
	"github.com/palantir/log4j-sniffer/pkg/scan"
	"github.com/stretchr/testify/assert"
)

func TestScanner_ScanImages(t *testing.T) {
	t.Run("returns non-nil, finds matches in image", func(t *testing.T) {
		client := &mockDockerClient{
			imageFile: "../../../examples/docker/log4j.tar",
			imageSummary: types.ImageSummary{
				ID:       "sha256:0efeedfe8b8beed50fb60d77cefd4b3523f1d6562766aee17b0c064c31bb1921",
				RepoTags: []string{"bad"},
			},
		}
		count, err := ScanImages(context.Background(), scan.Config{}, io.Discard, io.Discard, client, "")
		assert.NoError(t, err)
		assert.Equal(t, int64(2), count)
	})
}
