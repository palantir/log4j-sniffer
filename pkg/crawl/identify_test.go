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

package crawl_test

import (
	"archive/zip"
	"bytes"
	"context"
	"errors"
	"io/fs"
	"testing"
	"time"

	"github.com/palantir/log4j-sniffer/pkg/archive"
	"github.com/palantir/log4j-sniffer/pkg/crawl"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestTgzIdentifierImplementsTimeout(t *testing.T) {
	identify := crawl.NewIdentifier(time.Millisecond, 0, nil, nil, func(ctx context.Context, path string, walkFn archive.FileWalkFn) error {
		time.Sleep(50 * time.Millisecond)
		select {
		case <-ctx.Done():
			return errors.New("context was cancelled")
		default:
			require.FailNow(t, "context should have been cancelled")
		}
		return nil
	})
	_, _, err := identify.Identify(context.Background(), "", stubDirEntry{
		name: "sdlkfjsldkjfs.tar.gz",
	})
	assert.EqualError(t, err, "context was cancelled")
}

func TestZipIdentifierImplementsTimeout(t *testing.T) {
	t.Run("implements timeout", func(t *testing.T) {
		identify := crawl.NewIdentifier(time.Millisecond, 0, emptyZipReadCloserProvider, func(ctx context.Context, r *zip.Reader, walkFn archive.FileWalkFn) error {
			time.Sleep(50 * time.Millisecond)
			select {
			case <-ctx.Done():
				return errors.New("context was cancelled")
			default:
				require.FailNow(t, "context should have been cancelled")
			}
			return nil
		}, nil)
		_, _, err := identify.Identify(context.Background(), "/path/on/disk", stubDirEntry{
			name: "foo.zip",
		})
		assert.EqualError(t, err, "context was cancelled")
	})

	t.Run("opens using provider", func(t *testing.T) {
		expectedErr := errors.New("err")
		identify := crawl.NewIdentifier(time.Second, 0, func(path string) (*zip.ReadCloser, error) {
			assert.Equal(t, "foo", path)
			return nil, expectedErr
		}, nil, nil)
		_, _, err := identify.Identify(context.Background(), "foo", stubDirEntry{name: ".zip"})
		require.Equal(t, expectedErr, err)
	})
}

func TestIdentifyFromFileName(t *testing.T) {
	for _, tc := range []struct {
		name    string
		in      string
		result  crawl.Finding
		version string
	}{{
		name: "empty filename",
	}, {
		name: "plain filename",
		in:   "foo",
	}, {
		name:    "log4j x.y.z vulnerable version",
		in:      "log4j-core-2.10.0.jar",
		result:  crawl.JarName,
		version: "2.10.0",
	}, {
		name: "invalid file extension",
		in:   "log4j-core-2.10.0.png",
	}, {
		name: "log4j patched version",
		in:   "log4j-core-2.17.0.jar",
	}, {
		name:    "log4j major minor vulnerable version",
		in:      "log4j-core-2.15.jar",
		result:  crawl.JarName,
		version: "2.15",
	}, {
		name: "log4j name not as start of filename",
		in:   "asdsadlog4j-core-2.14.1.jar",
	}, {
		name: "log4j name not as end of filename",
		in:   "log4j-core-2.14.1.jarf",
	}, {
		name:    "vulnerable release candidate",
		in:      "log4j-core-2.14.1-rc1.jar",
		result:  crawl.JarName,
		version: "2.14.1-rc1",
	}, {
		name:    "case-insensitive match",
		in:      "lOg4J-cOrE-2.14.0.jAr",
		result:  crawl.JarName,
		version: "2.14.0",
	}} {
		t.Run(tc.name, func(t *testing.T) {
			identify := crawl.NewIdentifier(time.Second, 0, emptyZipReadCloserProvider, func(ctx context.Context, r *zip.Reader, walkFn archive.FileWalkFn) error {
				// this is called for jars that are not identified as log4j
				// these cases are tested elsewhere so we just return nil with no error her
				return nil
			}, panicOnWalk)
			result, version, err := identify.Identify(context.Background(), "/path/on/disk", stubDirEntry{
				name: tc.in,
			})
			require.NoError(t, err)
			assert.Equal(t, tc.result.String(), result.String())
			if tc.version == "" {
				assert.Empty(t, version)
			} else {
				assert.Equal(t, crawl.Versions{tc.version: {}}, version)
			}
		})
	}
}

func TestIdentifyFromZipContents(t *testing.T) {
	t.Run("handles error", func(t *testing.T) {
		expectedErr := errors.New("err")
		identify := crawl.NewIdentifier(time.Second, 0, emptyZipReadCloserProvider, func(ctx context.Context, r *zip.Reader, walkFn archive.FileWalkFn) error {
			return expectedErr
		}, panicOnWalk)
		_, _, err := identify.Identify(context.Background(), "/path/on/disk", stubDirEntry{
			name: "file.zip",
		})
		require.Equal(t, expectedErr, err)
	})

	for _, tc := range []struct {
		name       string
		filename   string
		filesInZip []string
		filesInTar []string
		result     crawl.Finding
		version    string
	}{{
		name:       "archive with no log4j",
		filename:   "file.zip",
		filesInZip: []string{"foo.jar"},
	}, {
		name:       "archive with vulnerable log4j version",
		filename:   "file.zip",
		filesInZip: []string{"foo.jar", "log4j-core-2.14.1.jar"},
		result:     crawl.JarNameInsideArchive,
		version:    "2.14.1",
	}, {
		name:       "archive with vulnerable log4j version in folder",
		filename:   "file.zip",
		filesInZip: []string{"foo.jar", "lib/log4j-core-2.14.1.jar"},
		result:     crawl.JarNameInsideArchive,
		version:    "2.14.1",
	}, {
		name:       "tarred and gzipped with vulnerable log4j version",
		filename:   "file.tar.gz",
		filesInTar: []string{"foo.jar", "log4j-core-2.14.1.jar"},
		result:     crawl.JarNameInsideArchive,
		version:    "2.14.1",
	}, {
		name:       "tarred and gzipped with vulnerable log4j version, multiple . in filename",
		filename:   "foo.bar.tar.gz",
		filesInTar: []string{"foo.jar", "log4j-core-2.14.1.jar"},
		result:     crawl.JarNameInsideArchive,
		version:    "2.14.1",
	}, {
		name:       "archive with JndiManager class in wrong package",
		filename:   "java.jar",
		filesInZip: []string{"a/package/with/JndiManager.class"},
		result:     crawl.ClassName,
		version:    crawl.UnknownVersion,
	}, {
		name:       "non-log4j archive with JndiManager in the log4j package",
		filename:   "not-log4.jar",
		filesInZip: []string{"org/apache/logging/log4j/core/net/JndiManager.class"},
		result:     crawl.ClassPackageAndName,
		version:    crawl.UnknownVersion,
	}, {
		name:       "vulnerable log4j named jar with JndiManager class",
		filename:   "log4j-core-2.14.1.jar",
		filesInZip: []string{"org/apache/logging/log4j/core/net/JndiManager.class"},
		result:     crawl.JarName | crawl.ClassPackageAndName,
		version:    "2.14.1",
	}, {
		name:       "fixed log4j version with JndiManager class",
		filename:   "log4j-core-2.17.0.jar",
		filesInZip: []string{"org/apache/logging/log4j/core/net/JndiManager.class"},
		result:     crawl.NothingDetected,
	}, {
		name:       "zip with uppercase log4j inside",
		filename:   "foo.jar",
		filesInZip: []string{"log4j-core-2.14.1.jAr"},
		result:     crawl.JarNameInsideArchive,
		version:    "2.14.1",
	}} {
		t.Run(tc.name, func(t *testing.T) {
			// we only write the zip list once otherwise we will continue to recurse forever.
			var zipContentsWritten bool
			identify := crawl.NewIdentifier(time.Second, 0, emptyZipReadCloserProvider, func(ctx context.Context, r *zip.Reader, walkFn archive.FileWalkFn) error {
				if zipContentsWritten {
					return nil
				}
				zipContentsWritten = true
				for _, path := range tc.filesInZip {
					if _, err := walkFn(ctx, path, 0, bytes.NewReader(validEmptyZipContent(t))); err != nil {
						return err
					}
				}
				return nil
			}, func(ctx context.Context, path string, walkFn archive.FileWalkFn) error {
				assert.Equal(t, "/path/on/disk/", path)
				for _, s := range tc.filesInTar {
					if _, err := walkFn(ctx, s, 0, bytes.NewReader([]byte{})); err != nil {
						return err
					}
				}
				return nil
			})
			result, version, err := identify.Identify(context.Background(), "/path/on/disk/", stubDirEntry{
				name: tc.filename,
			})
			require.NoError(t, err)
			assert.Equal(t, tc.result.String(), result.String())
			if tc.version == "" {
				assert.Empty(t, version)
			} else {
				assert.Equal(t, crawl.Versions{tc.version: {}}, version)
			}
		})
	}
}

func validEmptyZipContent(t *testing.T) []byte {
	var buf bytes.Buffer
	require.NoError(t, zip.NewWriter(&buf).Close())
	return buf.Bytes()
}

func TestFindingString(t *testing.T) {
	for _, tc := range []struct {
		In  crawl.Finding
		Out string
	}{
		{},
		{crawl.ClassName, "ClassName"},
		{crawl.JarName, "JarName"},
		{crawl.JarNameInsideArchive, "JarNameInsideArchive"},
		{crawl.ClassPackageAndName, "ClassPackageAndName"},

		{crawl.ClassName | crawl.JarName, "ClassName,JarName"},
		{crawl.ClassName | crawl.ClassPackageAndName, "ClassName,ClassPackageAndName"},
		{crawl.ClassName | crawl.JarName | crawl.ClassPackageAndName, "ClassName,JarName,ClassPackageAndName"},
	} {
		t.Run(tc.Out, func(t *testing.T) {
			assert.Equal(t, tc.Out, tc.In.String())
		})
	}
}

func emptyZipReadCloserProvider(string) (*zip.ReadCloser, error) {
	return &zip.ReadCloser{}, nil
}

type stubDirEntry struct {
	name string
}

func (s stubDirEntry) Name() string {
	return s.name
}

func (s stubDirEntry) IsDir() bool {
	panic("not required")
}

func (s stubDirEntry) Type() fs.FileMode {
	panic("not required")
}

func (s stubDirEntry) Info() (fs.FileInfo, error) {
	panic("not required")
}

func panicOnWalk(ctx context.Context, path string, walkFn archive.FileWalkFn) error {
	panic("should not have been called")
}
