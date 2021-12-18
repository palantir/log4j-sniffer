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

package integration_test

import (
	"os/exec"
	"testing"

	"github.com/palantir/godel/v2/pkg/products"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestLog4jHash(t *testing.T) {
	cli, err := products.Bin("log4j-sniffer")
	require.NoError(t, err)

	cmd := exec.Command(cli, "identify", "../examples/single_bad_version/log4j-core-2.14.1.jar")
	output, err := cmd.CombinedOutput()
	require.NoError(t, err, "command %v failed with output:\n%s", cmd.Args, string(output))
	got := string(output)
	assert.Contains(t, got, "Hash of complete class: f1d630c48928096a484e4b95ccb162a0", "Complete hash")
	assert.Contains(t, got, "Hash of all bytecode instructions: 1d8363622029e3404f45b192a3d60dad-v0", "Bytecode hash")
}

