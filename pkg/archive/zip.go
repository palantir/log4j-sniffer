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
	"archive/zip"
	"bytes"
	"io"

	"github.com/palantir/log4j-sniffer/pkg/buffer"
)

// ZipReaderFromReader creates a new *zip.Reader from the given io.Reader, r.
// The full contents of r are read into memory to be able to create an io.ReaderAt
// and know the size of the buffer for the zip.NewReader function.
// limit is the maximum number of bytes to read to create the zip.Reader.
func ZipReaderFromReader(r io.Reader, limit int) (*zip.Reader, error) {
	buf := buffer.NewSizeLimitedBuffer(limit)
	if _, err := io.Copy(&buf, r); err != nil {
		return nil, err
	}
	reader := bytes.NewReader(buf.Bytes())
	return zip.NewReader(reader, reader.Size())
}
