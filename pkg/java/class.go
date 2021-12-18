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

	for _, method := range classFile.Methods {
		for _, attribute := range method.AttributeTable {
			switch t := attribute.(type) {
			default:
				// ignore
			case classfile.CodeAttribute:
				code, i := t.Code, 0
				for i < len(code) {
					opcode := code[i]
					h.Write([]byte{opcode})

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
