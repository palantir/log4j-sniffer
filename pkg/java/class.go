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
	"bytes"
	md52 "crypto/md5"
	"errors"
	"fmt"

	"github.com/zxh0/jvm.go/classfile"
)

// HashClassInstructions produces a hash of the opcodes that define the methods
// of the specified class. This is intended to not change if the
// package name or other details are changed with the resulting
// changes to the non-opcode parts of the class format.
func HashClassInstructions(classBytes []byte) (string, error) {
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
					operands, err := opcodeOperands(opcode, opcodes)
					if err != nil {
						return "", err
					}
					i += operands + 1
				}
			}
		}
	}
	return fmt.Sprintf("%x-v0", h.Sum(nil)), nil
}

func ExtractBytecode(classBytes []byte) ([][]byte, error) {
	classFile, err := classfile.Parse(classBytes)
	if err != nil {
		return nil, err
	}

	var bytecode [][]byte
	opcodes := OpcodeLookupTables()

	for _, method := range classFile.Methods {
		for _, attribute := range method.AttributeTable {
			switch t := attribute.(type) {
			default:
				// ignore
			case classfile.CodeAttribute:
				code, i, extracted := t.Code, 0, bytes.Buffer{}
				for i < len(code) {
					opcode := code[i]
					extracted.WriteByte(opcode)

					operands, err := opcodeOperands(opcode, opcodes)
					if err != nil {
						return nil, err
					}
					i += operands + 1
				}
				bytecode = append(bytecode, extracted.Bytes())
			}
		}
	}
	return bytecode, nil
}

func opcodeOperands(opcode byte, opcodes Opcodes) (int, error) {
	// Look in the opcode tables to see how many operands
	// this opcode takes, and advance to the end which must
	// be another opcode or the end of the bytecode
	if opcodes.NoOperandOpcodeLookupTable[opcode] {
		return 0, nil
	} else if opcodes.SingleOperandOpcodeLookupTable[opcode] {
		return 1, nil
	} else if opcodes.DoubleOperandOpcodeLookupTable[opcode] {
		return 2, nil
	} else if opcodes.QuadOperandOpcodeLookupTable[opcode] {
		return 4, nil
	} else {
		for _, tripleOpcode := range opcodes.TripleOperandOpcodes {
			if opcode == tripleOpcode {
				return 3, nil
			}
		}
		// These opcodes take a variable amount of data and are not used
		// in log4j. We're ignoring them for now as a result.
		for _, otherOpcode := range opcodes.OtherOpcodes {
			if opcode == otherOpcode {
				return -1, errors.New("unsupported opcode type")
			}
		}
		return -1, errors.New("unrecognised opcode")
	}
}
