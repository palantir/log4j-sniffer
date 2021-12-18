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

package bytecode

import (
	"fmt"

	"github.com/palantir/log4j-sniffer/pkg/java"
)

func IdentifyClassFromBytecode(jarFile string, className string) error {
	hashes, err := java.HashClass(jarFile, className)
	if err != nil {
		return err
	}
	fmt.Printf("Hash of complete class: %s\n", hashes.CompleteHash)
	fmt.Printf("Hash of all bytecode instructions: %s\n", hashes.BytecodeInstructionHash)
	return nil
}
