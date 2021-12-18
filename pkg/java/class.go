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

package java

import (
	md52 "crypto/md5"
	"errors"
	"fmt"
	"io"
	"io/fs"

	"github.com/zxh0/jvm.go/classfile"
)

// This produces a hash of the opcodes that define the methods
// of the specified class. This is intended to not change if the
// package name or other details are changed with the resulting
// changes to the non-opcode parts of the class format.
func HashClassInstructions(class fs.File) (string, error) {
	stat, err := class.Stat()
	if err != nil {
		return "", err
	}
	classBytes := make([]byte, stat.Size())
	_, err = class.Read(classBytes)
	if err != nil && err != io.EOF {
		return "", err
	}
	classFile, err := classfile.Parse(classBytes)

	if err != nil {
		return "", err
	}

	h := md52.New()
	opcodes := OpcodeLookupTables()

	// Classes are made up of lots of things, but we only care
	// about the code that defines methods here. Iterate down
	// to just that.
	for _, method := range classFile.Methods {
		for _, attribute := range method.AttributeTable {
			switch t := attribute.(type) {
			default:
				// ignore
			case classfile.CodeAttribute:
				// Get the raw bytes for the bytecode for this method
				// Each opcode is exactly one byte in this array
				// We advance i past any operands for the opcode such
				// that reading i at any point will always result in
				// an opcode.
				code, i := t.Code, 0
				for i < len(code) {
					opcode := code[i]
					h.Write([]byte{opcode})

					// Look in the opcode tables to see how many operands
					// this opcode takes, and advance to the end which must
					// be another opcode or the end of the bytecode
					if opcodes.NoOperandOpcodeLookupTable[opcode] {
						i++
					} else if opcodes.SingleOperandOpcodeLookupTable[opcode] {
						i += 2
					} else if opcodes.DoubleOperandOpcodeLookupTable[opcode] {
						i += 3
					} else if opcodes.QuadOperandOpcodeLookupTable[opcode] {
						i += 5
					} else {
						for _, tripleOpcode := range opcodes.TripleOperandOpcodes {
							if opcode == tripleOpcode {
								i += 4
								continue
							}
						}
						// These opcodes take a variable amount of data and are not used
						// in log4j. We're ignoring them for now as a result.
						for _, otherOpcode := range opcodes.OtherOpcodes {
							if opcode == otherOpcode {
								return "", errors.New("unsupported opcode type")
							}
						}
						return "", errors.New("unrecognised opcode")
					}
				}
			}
		}
	}

	return fmt.Sprintf("%x-v0", h.Sum(nil)), nil
}
