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

package crawl_test

import (
	"testing"

	"github.com/palantir/log4j-sniffer/pkg/crawl"
	"github.com/stretchr/testify/assert"
)

func TestAllFindingsSatisfiedBy(t *testing.T) {
	t.Run("no finding requirement returns true for any", func(t *testing.T) {
		assert.True(t, crawl.AllFindingsSatisfiedBy(crawl.NothingDetected, crawl.NothingDetected))
		assert.True(t, crawl.AllFindingsSatisfiedBy(crawl.NothingDetected, 1))
	})

	t.Run("non-zero requirement does not match nothing detected", func(t *testing.T) {
		assert.False(t, crawl.AllFindingsSatisfiedBy(0b1, 0b0))
	})

	t.Run("exact bit match does match", func(t *testing.T) {
		assert.True(t, crawl.AllFindingsSatisfiedBy(0b1, 0b1))
	})

	t.Run("actual finding missing bits does not match", func(t *testing.T) {
		assert.False(t, crawl.AllFindingsSatisfiedBy(0b11, 0b1))
	})
}
