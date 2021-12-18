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
	"archive/zip"
	md52 "crypto/md5"
	"fmt"
	"io"
	"io/fs"
	"strings"
)

type ClassHash struct {
	CompleteHash            string
	BytecodeInstructionHash string
}

var emptyHash = ClassHash{
	CompleteHash:            "",
	BytecodeInstructionHash: "",
}

func HashClass(jarFile string, className string) (ClassHash, error) {
	r, err := zip.OpenReader(jarFile)
	if err != nil {
		return emptyHash, err
	}

	classLocation := strings.ReplaceAll(className, ".", "/")
	c, err := r.Open(classLocation + ".class")
	if err != nil {
		return emptyHash, err
	}

	completeHash, err := md5File(c)
	if err != nil {
		return emptyHash, err
	}

	c2, err := r.Open(classLocation + ".class")
	if err != nil {
		return emptyHash, err
	}
	bytecodeHash, err := HashClassInstructions(c2)
	if err != nil {
		return emptyHash, err
	}

	err = c.Close()
	if err != nil {
		return emptyHash, err
	}
	err = r.Close()
	if err != nil {
		return emptyHash, err
	}

	return ClassHash{
		CompleteHash:            completeHash,
		BytecodeInstructionHash: bytecodeHash,
	}, nil
}

func md5File(file fs.File) (string, error) {
	h := md52.New()
	if _, err := io.Copy(h, file); err != nil {
		return "", err
	}
	return fmt.Sprintf("%x", h.Sum(nil)), nil
}
