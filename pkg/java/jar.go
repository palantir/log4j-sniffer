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
	"bytes"
	md52 "crypto/md5"
	"fmt"
	"io"
	"io/fs"
	"strings"
)

type ClassHash struct {
	ClassSize               int64
	CompleteHash            string
	BytecodeInstructionHash string
}

func HashClass(jarFile string, className string) (ClassHash, error) {
	r, err := zip.OpenReader(jarFile)
	if err != nil {
		return ClassHash{}, err
	}

	classLocation := strings.ReplaceAll(className, ".", "/")

	completeHash, size, err := md5Class(r, classLocation)
	if err != nil {
		return ClassHash{}, err
	}

	bytecodeHash, err := md5Bytecode(r, classLocation)
	if err != nil {
		return ClassHash{}, err
	}

	return ClassHash{
		ClassSize:               size,
		CompleteHash:            completeHash,
		BytecodeInstructionHash: bytecodeHash,
	}, nil
}

func ReadMethodByteCode(jarFile string, className string) (bytecode [][]byte, err error) {
	r, err := zip.OpenReader(jarFile)
	if err != nil {
		return nil, err
	}
	defer func() {
		if cErr := r.Close(); err == nil && cErr != nil {
			err = cErr
		}
	}()

	classLocation := strings.ReplaceAll(className, ".", "/")

	buf, err := readClassBytes(r, classLocation)
	if err != nil {
		return nil, err
	}

	return ExtractBytecode(buf.Bytes())
}

func md5Class(r *zip.ReadCloser, classLocation string) (string, int64, error) {
	c, err := r.Open(classLocation + ".class")
	if err != nil {
		return "", 0, err
	}

	h, size, err := md5File(c)
	if err != nil {
		return "", 0, err
	}

	if err := c.Close(); err != nil {
		return "", 0, err
	}
	return h, size, nil
}

func md5File(file fs.File) (string, int64, error) {
	h := md52.New()
	size, err := io.Copy(h, file)
	if err != nil {
		return "", 0, err
	}
	return fmt.Sprintf("%x", h.Sum(nil)), size, nil
}

func md5Bytecode(r *zip.ReadCloser, classLocation string) (string, error) {
	buf, err := readClassBytes(r, classLocation)
	if err != nil {
		return "", err
	}

	h, err := HashClassInstructions(buf.Bytes())
	if err != nil {
		return "", err
	}

	return h, nil
}

func readClassBytes(r *zip.ReadCloser, classLocation string) (*bytes.Buffer, error) {
	c, err := r.Open(classLocation + ".class")
	if err != nil {
		return nil, err
	}

	buf := new(bytes.Buffer)
	_, err = buf.ReadFrom(c)
	if err != nil {
		return nil, err
	}

	if err = c.Close(); err != nil {
		return nil, err
	}
	return buf, nil
}
