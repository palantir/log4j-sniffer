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

// When hashing bytecode we care only about the opcodes and not
// the operands they take as the former is relatively static when
// shading or obfuscating classfiles while the latter varies significantly
//
// These tables are intended to use memory (1mb per number of operands) in
// order to speed up lookups. Total memory use remains reasonable as these
// are shared between all uses.
type Opcodes struct {
	NoOperandOpcodeLookupTable     []bool
	SingleOperandOpcodeLookupTable []bool
	DoubleOperandOpcodeLookupTable []bool
	QuadOperandOpcodeLookupTable   []bool
	TripleOperandOpcodes           []uint8
	OtherOpcodes                   []uint8
}

var NoOperandOpcodes = make([]bool, 0xff)

func setNoOperandOpcodes() {
	NoOperandOpcodes[0x00] = true // nop
	NoOperandOpcodes[0x01] = true // aconst_null
	NoOperandOpcodes[0x02] = true // iconst_m1
	NoOperandOpcodes[0x03] = true // iconst_0
	NoOperandOpcodes[0x04] = true // iconst_1
	NoOperandOpcodes[0x05] = true // iconst_2
	NoOperandOpcodes[0x06] = true // iconst_3
	NoOperandOpcodes[0x07] = true // iconst_4
	NoOperandOpcodes[0x08] = true // iconst_5
	NoOperandOpcodes[0x09] = true // lconst_0
	NoOperandOpcodes[0x0a] = true // lconst_1
	NoOperandOpcodes[0x0b] = true // fconst_0
	NoOperandOpcodes[0x0c] = true // fconst_1
	NoOperandOpcodes[0x0d] = true // fconst_2
	NoOperandOpcodes[0x0e] = true // dconst_0
	NoOperandOpcodes[0x0f] = true // dconst_1
	NoOperandOpcodes[0x1a] = true // iload_0
	NoOperandOpcodes[0x1b] = true // iload_1
	NoOperandOpcodes[0x1c] = true // iload_2
	NoOperandOpcodes[0x1d] = true // iload_3
	NoOperandOpcodes[0x1e] = true // lload_0
	NoOperandOpcodes[0x1f] = true // lload_1
	NoOperandOpcodes[0x20] = true // lload_2
	NoOperandOpcodes[0x21] = true // lload_3
	NoOperandOpcodes[0x22] = true // fload_0
	NoOperandOpcodes[0x23] = true // fload_1
	NoOperandOpcodes[0x24] = true // fload_2
	NoOperandOpcodes[0x25] = true // fload_3
	NoOperandOpcodes[0x26] = true // dload_0
	NoOperandOpcodes[0x27] = true // dload_1
	NoOperandOpcodes[0x28] = true // dload_2
	NoOperandOpcodes[0x29] = true // dload_3
	NoOperandOpcodes[0x2a] = true // aload_0
	NoOperandOpcodes[0x2b] = true // aload_1
	NoOperandOpcodes[0x2c] = true // aload_2
	NoOperandOpcodes[0x2d] = true // aload_3
	NoOperandOpcodes[0x2e] = true // iaload
	NoOperandOpcodes[0x2f] = true // laload
	NoOperandOpcodes[0x30] = true // faload
	NoOperandOpcodes[0x31] = true // daload
	NoOperandOpcodes[0x32] = true // aaload
	NoOperandOpcodes[0x33] = true // baload
	NoOperandOpcodes[0x34] = true // caload
	NoOperandOpcodes[0x35] = true // saload
	NoOperandOpcodes[0x3b] = true // istore_0
	NoOperandOpcodes[0x3c] = true // istore_1
	NoOperandOpcodes[0x3d] = true // istore_2
	NoOperandOpcodes[0x3e] = true // istore_3
	NoOperandOpcodes[0x3f] = true // lstore_0
	NoOperandOpcodes[0x40] = true // lstore_1
	NoOperandOpcodes[0x41] = true // lstore_2
	NoOperandOpcodes[0x42] = true // lstore_3
	NoOperandOpcodes[0x43] = true // fstore_0
	NoOperandOpcodes[0x44] = true // fstore_1
	NoOperandOpcodes[0x45] = true // fstore_2
	NoOperandOpcodes[0x46] = true // fstore_3
	NoOperandOpcodes[0x47] = true // dstore_0
	NoOperandOpcodes[0x48] = true // dstore_1
	NoOperandOpcodes[0x49] = true // dstore_2
	NoOperandOpcodes[0x4a] = true // dstore_3
	NoOperandOpcodes[0x4b] = true // astore_0
	NoOperandOpcodes[0x4c] = true // astore_1
	NoOperandOpcodes[0x4d] = true // astore_2
	NoOperandOpcodes[0x4e] = true // astore_3
	NoOperandOpcodes[0x4f] = true // iastore
	NoOperandOpcodes[0x50] = true // lastore
	NoOperandOpcodes[0x51] = true // fastore
	NoOperandOpcodes[0x52] = true // dastore
	NoOperandOpcodes[0x53] = true // aastore
	NoOperandOpcodes[0x54] = true // bastore
	NoOperandOpcodes[0x55] = true // castore
	NoOperandOpcodes[0x56] = true // sastore
	NoOperandOpcodes[0x57] = true // pop
	NoOperandOpcodes[0x58] = true // pop2
	NoOperandOpcodes[0x59] = true // dup
	NoOperandOpcodes[0x5a] = true // dup_x1
	NoOperandOpcodes[0x5b] = true // dup_x2
	NoOperandOpcodes[0x5c] = true // dup2
	NoOperandOpcodes[0x5d] = true // dup2_x1
	NoOperandOpcodes[0x5e] = true // dup2_x2
	NoOperandOpcodes[0x5f] = true // swap
	NoOperandOpcodes[0x60] = true // iadd
	NoOperandOpcodes[0x61] = true // ladd
	NoOperandOpcodes[0x62] = true // fadd
	NoOperandOpcodes[0x63] = true // dadd
	NoOperandOpcodes[0x64] = true // isub
	NoOperandOpcodes[0x65] = true // lsub
	NoOperandOpcodes[0x66] = true // fsub
	NoOperandOpcodes[0x67] = true // dsub
	NoOperandOpcodes[0x68] = true // imul
	NoOperandOpcodes[0x69] = true // lmul
	NoOperandOpcodes[0x6a] = true // fmul
	NoOperandOpcodes[0x6b] = true // dmul
	NoOperandOpcodes[0x6c] = true // idiv
	NoOperandOpcodes[0x6d] = true // ldiv
	NoOperandOpcodes[0x6e] = true // fdiv
	NoOperandOpcodes[0x6f] = true // ddiv
	NoOperandOpcodes[0x70] = true // irem
	NoOperandOpcodes[0x71] = true // lrem
	NoOperandOpcodes[0x72] = true // frem
	NoOperandOpcodes[0x73] = true // drem
	NoOperandOpcodes[0x74] = true // ineg
	NoOperandOpcodes[0x75] = true // lneg
	NoOperandOpcodes[0x76] = true // fneg
	NoOperandOpcodes[0x77] = true // dneg
	NoOperandOpcodes[0x78] = true // ishl
	NoOperandOpcodes[0x79] = true // lshl
	NoOperandOpcodes[0x7a] = true // ishr
	NoOperandOpcodes[0x7b] = true // lshr
	NoOperandOpcodes[0x7c] = true // iushr
	NoOperandOpcodes[0x7d] = true // lushr
	NoOperandOpcodes[0x7e] = true // iand
	NoOperandOpcodes[0x7f] = true // land
	NoOperandOpcodes[0x80] = true // ior
	NoOperandOpcodes[0x81] = true // lor
	NoOperandOpcodes[0x82] = true // ixor
	NoOperandOpcodes[0x83] = true // lxor
	NoOperandOpcodes[0x85] = true // i2l
	NoOperandOpcodes[0x86] = true // i2f
	NoOperandOpcodes[0x87] = true // i2d
	NoOperandOpcodes[0x88] = true // l2i
	NoOperandOpcodes[0x89] = true // l2f
	NoOperandOpcodes[0x8a] = true // l2d
	NoOperandOpcodes[0x8b] = true // f2i
	NoOperandOpcodes[0x8c] = true // f2l
	NoOperandOpcodes[0x8d] = true // f2d
	NoOperandOpcodes[0x8e] = true // d2i
	NoOperandOpcodes[0x8f] = true // d2l
	NoOperandOpcodes[0x90] = true // d2f
	NoOperandOpcodes[0x91] = true // i2b
	NoOperandOpcodes[0x92] = true // i2c
	NoOperandOpcodes[0x93] = true // i2s
	NoOperandOpcodes[0x94] = true // lcmp
	NoOperandOpcodes[0x95] = true // fcmpl
	NoOperandOpcodes[0x96] = true // fcmpg
	NoOperandOpcodes[0x97] = true // dcmpl
	NoOperandOpcodes[0x98] = true // dcmpg
	NoOperandOpcodes[0xac] = true // ireturn
	NoOperandOpcodes[0xad] = true // lreturn
	NoOperandOpcodes[0xae] = true // freturn
	NoOperandOpcodes[0xaf] = true // dreturn
	NoOperandOpcodes[0xb0] = true // areturn
	NoOperandOpcodes[0xb1] = true // return
	NoOperandOpcodes[0xbe] = true // arraylength
	NoOperandOpcodes[0xbf] = true // athrow
	NoOperandOpcodes[0xc2] = true // monitorenter
	NoOperandOpcodes[0xc3] = true // monitorexit
}

var SingleOperandOpcodes = make([]bool, 0xff)

func setSingleOperandOpcodes() {
	SingleOperandOpcodes[0xbc] = true // newarray
	SingleOperandOpcodes[0x10] = true // bipush
	SingleOperandOpcodes[0x12] = true // ldc
	SingleOperandOpcodes[0x15] = true // iload
	SingleOperandOpcodes[0x16] = true // lload
	SingleOperandOpcodes[0x17] = true // fload
	SingleOperandOpcodes[0x18] = true // dload
	SingleOperandOpcodes[0x19] = true // aload
	SingleOperandOpcodes[0x36] = true // istore
	SingleOperandOpcodes[0x37] = true // lstore
	SingleOperandOpcodes[0x38] = true // fstore
	SingleOperandOpcodes[0x39] = true // dstore
	SingleOperandOpcodes[0x3a] = true // astore
	SingleOperandOpcodes[0xa9] = true // ret
}

var DoubleOperandOpcodes = make([]bool, 0xff)

func setDoubleOperandOpcodes() {
	DoubleOperandOpcodes[0x99] = true // ifeq
	DoubleOperandOpcodes[0x9a] = true // ifne
	DoubleOperandOpcodes[0x9b] = true // iflt
	DoubleOperandOpcodes[0x9c] = true // ifge
	DoubleOperandOpcodes[0x9d] = true // ifgt
	DoubleOperandOpcodes[0x9e] = true // ifle
	DoubleOperandOpcodes[0x9f] = true // if_icmpeq
	DoubleOperandOpcodes[0xa0] = true // if_icmpne
	DoubleOperandOpcodes[0xa1] = true // if_icmplt
	DoubleOperandOpcodes[0xa2] = true // if_icmpge
	DoubleOperandOpcodes[0xa3] = true // if_icmpgt
	DoubleOperandOpcodes[0xa4] = true // if_icmple
	DoubleOperandOpcodes[0xa5] = true // if_acmpeq
	DoubleOperandOpcodes[0xa6] = true // if_acmpne
	DoubleOperandOpcodes[0xa7] = true // goto
	DoubleOperandOpcodes[0xa8] = true // jsr
	DoubleOperandOpcodes[0xc6] = true // ifnull
	DoubleOperandOpcodes[0xc7] = true // ifnonnull
	DoubleOperandOpcodes[0x11] = true // sipush
	DoubleOperandOpcodes[0x84] = true // iinc
	DoubleOperandOpcodes[0x13] = true // ldc_w
	DoubleOperandOpcodes[0x14] = true // ldc2_w
	DoubleOperandOpcodes[0xb2] = true // getstatic
	DoubleOperandOpcodes[0xb3] = true // putstatic
	DoubleOperandOpcodes[0xb4] = true // getfield
	DoubleOperandOpcodes[0xb5] = true // putfield
	DoubleOperandOpcodes[0xb6] = true // invokevirtual
	DoubleOperandOpcodes[0xb7] = true // invokespecial
	DoubleOperandOpcodes[0xb8] = true // invokestatic
	DoubleOperandOpcodes[0xbb] = true // new
	DoubleOperandOpcodes[0xbd] = true // anewarray
	DoubleOperandOpcodes[0xc0] = true // checkcast
	DoubleOperandOpcodes[0xc1] = true // instanceof
}

var QuadOperandOpcodes = make([]bool, 0xff)

func setQuadOperandOpcodes() {
	QuadOperandOpcodes[0xc8] = true // goto_w
	QuadOperandOpcodes[0xc9] = true // jsr_w
	QuadOperandOpcodes[0xba] = true // invokedynamic
	QuadOperandOpcodes[0xb9] = true // invokeinterface
}

var TripleOperandOpcodes = []uint8{0xc5}

// Opcodes that are either reserved or take a variable number of operands
var OtherOpcodes = []uint8{0xc4, 0xab, 0xaa, 0xfe, 0xff, 0xca}

var OpcodesInitialised = false

func OpcodeLookupTables() Opcodes {
	if !OpcodesInitialised {
		setNoOperandOpcodes()
		setSingleOperandOpcodes()
		setDoubleOperandOpcodes()
		setQuadOperandOpcodes()
		OpcodesInitialised = true
	}

	return Opcodes{
		NoOperandOpcodeLookupTable:     NoOperandOpcodes,
		SingleOperandOpcodeLookupTable: SingleOperandOpcodes,
		DoubleOperandOpcodeLookupTable: DoubleOperandOpcodes,
		QuadOperandOpcodeLookupTable:   QuadOperandOpcodes,
		TripleOperandOpcodes:           TripleOperandOpcodes,
		OtherOpcodes:                   OtherOpcodes,
	}
}
