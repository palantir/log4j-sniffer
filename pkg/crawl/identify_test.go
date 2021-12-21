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
	"os"
	"testing"
	"time"

	"github.com/palantir/log4j-sniffer/pkg/archive"
	"github.com/palantir/log4j-sniffer/pkg/crawl"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/ratelimit"
)

func TestTgzIdentifierImplementsTimeout(t *testing.T) {
	ientifier := crawl.Log4jIdentifier{
		TarWalker: func(ctx context.Context, path string, getTarReader archive.TarReaderProvider, walkFn archive.FileWalkFn) error {
			time.Sleep(50 * time.Millisecond)
			select {
			case <-ctx.Done():
				return errors.New("context was cancelled")
			default:
				require.FailNow(t, "context should have been cancelled")
			}
			return nil
		},
		ArchiveWalkTimeout: time.Millisecond,
		Limiter:            ratelimit.NewUnlimited(),
	}

	_, _, err := ientifier.Identify(context.Background(), "", stubDirEntry{
		name: "sdlkfjsldkjfs.tar.gz",
	})
	assert.EqualError(t, err, "context was cancelled")
}

func TestZipIdentifierImplementsTimeout(t *testing.T) {
	t.Run("implements timeout", func(t *testing.T) {
		identifier := crawl.Log4jIdentifier{
			OpenFileZipReader: emptyZipReadCloserProvider,
			ZipWalker: func(ctx context.Context, r *zip.Reader, walkFn archive.FileWalkFn) error {
				time.Sleep(50 * time.Millisecond)
				select {
				case <-ctx.Done():
					return errors.New("context was cancelled")
				default:
					require.FailNow(t, "context should have been cancelled")
				}
				return nil
			},
			ArchiveWalkTimeout: time.Millisecond,
			Limiter:            ratelimit.NewUnlimited(),
		}

		_, _, err := identifier.Identify(context.Background(), "/path/on/disk", stubDirEntry{
			name: "foo.zip",
		})
		assert.EqualError(t, err, "context was cancelled")
	})

	t.Run("opens using provider", func(t *testing.T) {
		expectedErr := errors.New("err")
		identifier := crawl.Log4jIdentifier{
			OpenFileZipReader: func(path string) (*zip.ReadCloser, error) {
				assert.Equal(t, "foo", path)
				return nil, expectedErr
			},
			ArchiveWalkTimeout: time.Second,
			Limiter:            ratelimit.NewUnlimited(),
		}

		_, _, err := identifier.Identify(context.Background(), "foo", stubDirEntry{name: ".zip"})
		require.Equal(t, expectedErr, err)
	})

	t.Run("does not recurse into nested archives when ArchiveMaxDepth set to 0", func(t *testing.T) {
		identifier := crawl.Log4jIdentifier{
			OpenFileZipReader: func(path string) (*zip.ReadCloser, error) {
				zipContent := createZipContent(t, "nested.zip",
					createZipContent(t, "log4j-core-2.14.1.jar", []byte{}).Bytes())
				return zip.OpenReader(mustWriteTempFile(t, "outer.z", zipContent.Bytes()))
			},
			ZipWalker:          archive.WalkZipFiles,
			ArchiveWalkTimeout: time.Second,
			ArchiveMaxSize:     1024,
			Limiter:            ratelimit.NewUnlimited(),
		}

		finding, version, err := identifier.Identify(context.Background(), "ignored", stubDirEntry{name: ".zip"})
		require.NoError(t, err)
		assert.Equal(t, crawl.NothingDetected, finding)
		assert.Equal(t, crawl.Versions{}, version)
	})

	t.Run("supports nested archives", func(t *testing.T) {
		identifier := crawl.Log4jIdentifier{
			OpenFileZipReader: func(path string) (*zip.ReadCloser, error) {
				zipContent := createZipContent(t, "nested.zip",
					createZipContent(t, "log4j-core-2.14.1.jar", emptyZipContent(t)).Bytes())
				return zip.OpenReader(mustWriteTempFile(t, "outer.z", zipContent.Bytes()))
			},
			ZipWalker:          archive.WalkZipFiles,
			ArchiveWalkTimeout: time.Second,
			ArchiveMaxDepth:    10,
			ArchiveMaxSize:     1024,
			Limiter:            ratelimit.NewUnlimited(),
		}

		finding, version, err := identifier.Identify(context.Background(), "ignored", stubDirEntry{name: ".zip"})
		require.NoError(t, err)
		assert.Equal(t, crawl.JarNameInsideArchive, finding)
		assert.Equal(t, crawl.Versions{"2.14.1": {}}, version)
	})

	t.Run("errors when archive too large", func(t *testing.T) {
		identifier := crawl.Log4jIdentifier{
			OpenFileZipReader: func(path string) (*zip.ReadCloser, error) {
				zipContent := createZipContent(t, "nested.zip",
					createZipContent(t, "log4j-core-2.14.1.jar", []byte{}).Bytes())
				return zip.OpenReader(mustWriteTempFile(t, "outer.z", zipContent.Bytes()))
			},
			ZipWalker:          archive.WalkZipFiles,
			ArchiveWalkTimeout: time.Second,
			ArchiveMaxDepth:    10,
			ArchiveMaxSize:     1,
			Limiter:            ratelimit.NewUnlimited(),
		}

		_, _, err := identifier.Identify(context.Background(), "ignored", stubDirEntry{name: ".zip"})
		require.EqualError(t, err, "creating zip reader from reader: write would exceed buffer maximum: 1")
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
			identifier := crawl.Log4jIdentifier{
				OpenFileZipReader: emptyZipReadCloserProvider,
				ZipWalker: func(ctx context.Context, r *zip.Reader, walkFn archive.FileWalkFn) error {
					// this is called for jars that are not identified as log4j
					// these cases are tested elsewhere so we just return nil with no error her
					return nil
				},
				ArchiveWalkTimeout: time.Second,
				Limiter:            ratelimit.NewUnlimited(),
			}

			result, version, err := identifier.Identify(context.Background(), "/path/on/disk", stubDirEntry{
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
		identifier := crawl.Log4jIdentifier{
			OpenFileZipReader: emptyZipReadCloserProvider,
			ZipWalker: func(ctx context.Context, r *zip.Reader, walkFn archive.FileWalkFn) error {
				return expectedErr
			},
			ArchiveWalkTimeout: time.Second,
			Limiter:            ratelimit.NewUnlimited(),
		}

		_, _, err := identifier.Identify(context.Background(), "/path/on/disk", stubDirEntry{
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
		result:     crawl.JndiManagerClassName,
		version:    crawl.UnknownVersion,
	}, {
		name:       "non-log4j archive with JndiManager in the log4j package",
		filename:   "not-log4.jar",
		filesInZip: []string{"org/apache/logging/log4j/core/net/JndiManager.class"},
		result:     crawl.JndiManagerClassPackageAndName,
		version:    crawl.UnknownVersion,
	}, {
		name:       "vulnerable log4j named jar with JndiManager class",
		filename:   "log4j-core-2.14.1.jar",
		filesInZip: []string{"org/apache/logging/log4j/core/net/JndiManager.class"},
		result:     crawl.JarName | crawl.JndiManagerClassPackageAndName,
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
	}, {
		name:       "JndiLookup class name hit",
		filename:   "foo.jar",
		filesInZip: []string{"a/b/JndiLookup.class"},
		result:     crawl.JndiLookupClassName,
		version:    crawl.UnknownVersion,
	}, {
		name:     "JndiLookup class name and package hit",
		filename: "log4j-core-2.14.1.jar",
		filesInZip: []string{"org/apache/logging/log4j/core/net/JndiManager.class",
			"org/apache/logging/log4j/core/lookup/JndiLookup.class"},
		result:  crawl.JarName | crawl.JndiLookupClassPackageAndName | crawl.JndiManagerClassPackageAndName,
		version: "2.14.1",
	}} {
		t.Run(tc.name, func(t *testing.T) {
			// we only write the zip list once otherwise we will continue to recurse forever.
			var zipContentsWritten bool
			identifier := crawl.Log4jIdentifier{
				OpenFileZipReader: emptyZipReadCloserProvider,
				ZipWalker: func(ctx context.Context, r *zip.Reader, walkFn archive.FileWalkFn) error {
					if zipContentsWritten {
						return nil
					}
					zipContentsWritten = true
					for _, path := range tc.filesInZip {
						if _, err := walkFn(ctx, path, 0, bytes.NewReader(emptyZipContent(t))); err != nil {
							return err
						}
					}
					return nil
				},
				TarWalker: func(ctx context.Context, path string, getTarReader archive.TarReaderProvider, walkFn archive.FileWalkFn) error {
					assert.Equal(t, "/path/on/disk/", path)
					for _, s := range tc.filesInTar {
						if _, err := walkFn(ctx, s, 0, bytes.NewReader([]byte{})); err != nil {
							return err
						}
					}
					return nil
				},
				ArchiveWalkTimeout: time.Second,
				Limiter:            ratelimit.NewUnlimited(),
			}
			result, version, err := identifier.Identify(context.Background(), "/path/on/disk/", stubDirEntry{
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

func TestFindingString(t *testing.T) {
	for _, tc := range []struct {
		In  crawl.Finding
		Out string
	}{
		{},
		{crawl.JndiManagerClassName, "JndiManagerClassName"},
		{crawl.JarName, "JarName"},
		{crawl.JarNameInsideArchive, "JarNameInsideArchive"},
		{crawl.JndiManagerClassPackageAndName, "JndiManagerClassPackageAndName"},
		{crawl.JndiManagerClassName | crawl.JarName, "JndiManagerClassName,JarName"},
		{crawl.JndiManagerClassName | crawl.JndiManagerClassPackageAndName, "JndiManagerClassName,JndiManagerClassPackageAndName"},
		{crawl.JndiManagerClassName | crawl.JarName | crawl.JndiManagerClassPackageAndName, "JndiManagerClassName,JarName,JndiManagerClassPackageAndName"},
		{crawl.JarName | crawl.JndiLookupClassPackageAndName, "JndiLookupClassPackageAndName,JarName"},
	} {
		t.Run(tc.Out, func(t *testing.T) {
			assert.Equal(t, tc.Out, tc.In.String())
		})
	}
}

func emptyZipReadCloserProvider(string) (*zip.ReadCloser, error) {
	return &zip.ReadCloser{}, nil
}

func mustWriteTempFile(t *testing.T, name string, content []byte) string {
	t.Helper()
	temp, err := os.CreateTemp(t.TempDir(), name)
	require.NoError(t, err)
	_, err = temp.Write(content)
	require.NoError(t, err)
	require.NoError(t, temp.Close())
	return temp.Name()
}

func createZipContent(t *testing.T, containedFilename string, containedFileContent []byte) *bytes.Buffer {
	t.Helper()
	var buf bytes.Buffer
	w := zip.NewWriter(&buf)
	header, err := w.CreateHeader(&zip.FileHeader{
		Name: containedFilename,
	})
	require.NoError(t, err)
	_, err = header.Write(containedFileContent)
	require.NoError(t, err)
	require.NoError(t, w.Close())
	return &buf
}

func emptyZipContent(t *testing.T) []byte {
	var buf bytes.Buffer
	require.NoError(t, zip.NewWriter(&buf).Close())
	return buf.Bytes()
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
