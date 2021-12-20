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

package java_test

import (
	"fmt"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"testing"

	"github.com/palantir/log4j-sniffer/pkg/java"
)

func TestComparisonWithObfuscatedClass(t *testing.T) {
	comparison, err := java.CompareClasses("../../examples/multiple_bad_versions/log4j-core-2.14.1.jar",
		"org.apache.logging.log4j.core.net.JndiManager",
		"../../examples/obfuscated/2.14.1-aaaagb.jar",
		"org.a.a.a.a.g.b")

	require.NoError(t, err)

	var exactMatchesInHex []string
	for _, exactMatch := range comparison.ExactMatches {
		exactMatchesInHex = append(exactMatchesInHex, fmt.Sprintf("%x", exactMatch))
	}
	assert.Equal(t, exactMatchesInHex, []string{
		"2a012bb72a2cb5b1",
		"12b6b201b8c0b0",
		"2ab4b8ac",
		"2ab42bb9b0",
		"2a2b2cb7b1",
		"b2b0",
	})

	var partialMatchesInHex []string
	for _, partialMatch := range comparison.PartialMatches {
		hex := fmt.Sprintf("%x", partialMatch.Prefix)
		for i := 0; i < partialMatch.AmountSkipped; i++ {
			hex = fmt.Sprintf("%s_", hex)
		}
		hex = fmt.Sprintf( "%s%x", hex, partialMatch.Suffix)
		partialMatchesInHex = append(partialMatchesInHex, hex)
	}
	assert.Equal(t, partialMatchesInHex, []string {
		"bb59_____2ab4b612b62ab4b612b6b6b0",
		"bb59___b7b3b1",
	})

	var unmatchedInHex []string
	for _, notMatched := range comparison.FirstClassUnmatchedBytecode {
		unmatchedInHex = append(unmatchedInHex, fmt.Sprintf("%x", notMatched))
	}
	assert.Equal(t, unmatchedInHex, []string{
		"2ac701b0bb59b73a19122ab6572bc619122bb657a7b2122ab92cc619122cb6572dc619122db65719c6191219b657a7b2122db919c61919b619b0",
		"2a2b2c2d1919b83ab8b219b8c0b0",
		"bb59b712b6b610b612b6b6b6b0",
		"2ab201b8c0b0",
		"b8b22ab8c0b0",
	})

	assert.Empty(t, comparison.SecondClassUnmatchedBytecode)
}

func TestComparisonWithSelf(t *testing.T) {
	comparison, err := java.CompareClasses("../../examples/multiple_bad_versions/log4j-core-2.14.1.jar",
		"org.apache.logging.log4j.core.net.JndiManager",
		"../../examples/multiple_bad_versions/log4j-core-2.14.1.jar",
		"org.apache.logging.log4j.core.net.JndiManager")

	require.NoError(t, err)

	var hashes map[string]struct{} = make(map[string]struct{})
	for _, firstClassBytecode := range comparison.FirstClassMethodBytecode {
		hashes[fmt.Sprintf("%x", firstClassBytecode)] = struct{}{}
	}
	for _, secondClassBytecode := range comparison.SecondClassMethodBytecode {
		assert.NotNil(t, hashes[fmt.Sprintf("%x", secondClassBytecode)])
	}
	for _, matchedBytecode := range comparison.ExactMatches {
		assert.NotNil(t, hashes[fmt.Sprintf("%x", matchedBytecode)])
	}

	assert.Empty(t, comparison.PartialMatches)
	assert.Empty(t, comparison.FirstClassUnmatchedBytecode)
	assert.Empty(t, comparison.SecondClassUnmatchedBytecode)
}

