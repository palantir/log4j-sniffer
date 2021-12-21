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

package archive

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestCheckArchiveType(t *testing.T) {
	tests := []struct {
		filename string
		want     FormatType
		ok       bool
	}{
		{filename: "filename.zip", want: ZipArchive, ok: true},
		{filename: "fat_jar.jar", want: ZipArchive, ok: true},
		{filename: "many.dots.with.jar", want: ZipArchive, ok: true},
		{filename: ".dotfile.jar", want: ZipArchive, ok: true},
		{filename: "par_file.par", want: ZipArchive, ok: true},
		{filename: "generic.tar", want: TarArchive, ok: true},
		{filename: "many.dots.tar", want: TarArchive, ok: true},
		{filename: ".hidden-file.tar", want: TarArchive, ok: true},
		{filename: ".dotfile.many.tar", want: TarArchive, ok: true},
		{filename: "compressed.tar.gz", want: TarGzArchive, ok: true},
		{filename: "many.dots.tar.gz", want: TarGzArchive, ok: true},
		{filename: "compressed.tgz", want: TarGzArchive, ok: true},
		{filename: "bz2compressed.tar.bz2", want: TarBz2Archive, ok: true},
		{filename: "many.dots.tar.bz2", want: TarBz2Archive, ok: true},
		{filename: "bz2compressed.tbz2", want: TarBz2Archive, ok: true},
		{filename: "unsupported.jpg", want: UnsupportedArchive, ok: false},
		{filename: "file.with.many.extensions", want: UnsupportedArchive, ok: false},
		{filename: "no-extension", want: UnsupportedArchive, ok: false},
		{filename: "", want: UnsupportedArchive, ok: false},
	}
	for _, tt := range tests {
		t.Run(tt.filename, func(t *testing.T) {
			got, ok := ParseArchiveFormatFromFile(tt.filename)
			assert.Equal(t, got, tt.want)
			assert.Equal(t, ok, tt.ok)
		})
	}
}
