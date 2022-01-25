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
	"io"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/palantir/log4j-sniffer/pkg/archive"
	"github.com/palantir/log4j-sniffer/pkg/crawl"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/ratelimit"
)

func TestLog4jIdentifier(t *testing.T) {
	t.Run("implements timeout", func(t *testing.T) {
		identifier := crawl.Log4jIdentifier{
			ArchiveWalkers: func(path string) (archive.WalkerProvider, int64, bool) {
				assert.Equal(t, "bar", path)
				return archive.WalkerProviderFromFuncs(func(string) (archive.WalkFn, func() error, error) {
					return func(ctx context.Context, walkFn archive.FileWalkFn) error {
						time.Sleep(50 * time.Millisecond)
						select {
						case <-ctx.Done():
							return errors.New("context was cancelled")
						default:
							require.FailNow(t, "context should have been cancelled")
						}
						return nil
					}, noopCloser, nil
				}, nil), -1, true
			},
			ArchiveWalkTimeout: time.Millisecond,
			Limiter:            ratelimit.NewUnlimited(),
		}
		_, _, _, err := identifier.Identify(context.Background(), "foo/bar", "bar")
		assert.Error(t, err)
		assert.True(t, strings.HasSuffix(err.Error(), ": context was cancelled"))
	})

	t.Run("closes and returns close error", func(t *testing.T) {
		expectedErr := errors.New("err")
		identifier := crawl.Log4jIdentifier{
			ArchiveWalkers: func(string) (archive.WalkerProvider, int64, bool) {
				return archive.WalkerProviderFromFuncs(func(string) (archive.WalkFn, func() error, error) {
					return func(ctx context.Context, walkFn archive.FileWalkFn) error { return nil },
						func() error { return expectedErr }, nil
				}, nil), -1, true
			},
			ArchiveWalkTimeout: time.Second,
			Limiter:            ratelimit.NewUnlimited(),
		}
		_, _, _, err := identifier.Identify(context.Background(), "foo/sdlkfjsldkjfs.tar.gz", "sdlkfjsldkjfs.tar.gz")
		assert.Equal(t, expectedErr, err)
	})

	t.Run("does not recurse into nested archives when ArchiveMaxDepth set to 0", func(t *testing.T) {
		var fileWalkCalls int
		var readerWalkCalls int
		identifier := crawl.Log4jIdentifier{
			ArchiveWalkers: func(string) (archive.WalkerProvider, int64, bool) {
				return archive.WalkerProviderFromFuncs(
					func(string) (archive.WalkFn, func() error, error) {
						return func(ctx context.Context, walkFn archive.FileWalkFn) error {
							fileWalkCalls++
							_, _ = walkFn(ctx, "", 0, &bytes.Buffer{})
							return nil
						}, noopCloser, nil
					},
					func(r io.Reader) (archive.WalkFn, func() error, error) {
						return func(ctx context.Context, walkFn archive.FileWalkFn) error {
							readerWalkCalls++
							_, _ = walkFn(ctx, "", 0, &bytes.Buffer{})
							return nil
						}, noopCloser, nil
					}), -1, true
			},
			ArchiveWalkTimeout: time.Second,
			Limiter:            ratelimit.NewUnlimited(),
		}

		_, _, _, err := identifier.Identify(context.Background(), "ignored/.zip", ".zip")
		require.NoError(t, err)
		assert.Equal(t, 1, fileWalkCalls)
		assert.Equal(t, 0, readerWalkCalls)
	})

	t.Run("recurses expected amount when configured", func(t *testing.T) {
		var fileWalkCalls int
		var readerWalkCalls int
		identifier := crawl.Log4jIdentifier{
			ArchiveWalkers: func(string) (archive.WalkerProvider, int64, bool) {
				return archive.WalkerProviderFromFuncs(
					func(string) (archive.WalkFn, func() error, error) {
						return func(ctx context.Context, walkFn archive.FileWalkFn) error {
							fileWalkCalls++
							_, _ = walkFn(ctx, "", 0, &bytes.Buffer{})
							return nil
						}, noopCloser, nil
					},
					func(r io.Reader) (archive.WalkFn, func() error, error) {
						return func(ctx context.Context, walkFn archive.FileWalkFn) error {
							readerWalkCalls++
							_, _ = walkFn(ctx, "", 0, &bytes.Buffer{})
							return nil
						}, noopCloser, nil
					}), -1, true
			},
			ArchiveWalkTimeout: time.Second,
			ArchiveMaxDepth:    3,
			Limiter:            ratelimit.NewUnlimited(),
		}

		_, _, _, err := identifier.Identify(context.Background(), "ignored/.zip", ".zip")
		require.NoError(t, err)
		assert.Equal(t, 1, fileWalkCalls)
		assert.Equal(t, 3, readerWalkCalls)
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
		in:   "log4j-core-2.17.1.jar",
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
				ArchiveWalkTimeout: time.Second,
				Limiter:            ratelimit.NewUnlimited(),
				ArchiveWalkers: func(s string) (archive.WalkerProvider, int64, bool) {
					return nil, 0, false
				},
			}

			result, version, _, err := identifier.Identify(context.Background(), "/path/on/disk/"+tc.in, tc.in)
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

func TestIdentifyFromArchiveContents(t *testing.T) {
	for _, tc := range []struct {
		name           string
		filename       string
		filesInArchive []string
		result         crawl.Finding
		version        string
	}{{
		name:           "archive with no log4j",
		filename:       "file.zip",
		filesInArchive: []string{"foo.jar"},
	}, {
		name:           "archive with vulnerable log4j version",
		filename:       "file.zip",
		filesInArchive: []string{"foo.jar", "log4j-core-2.14.1.jar"},
		result:         crawl.JarNameInsideArchive,
		version:        "2.14.1",
	}, {
		name:           "archive with vulnerable log4j version in folder",
		filename:       "file.zip",
		filesInArchive: []string{"foo.jar", "lib/log4j-core-2.14.1.jar"},
		result:         crawl.JarNameInsideArchive,
		version:        "2.14.1",
	}, {
		name:           "tarred and gzipped with vulnerable log4j version",
		filename:       "file.tar.gz",
		filesInArchive: []string{"foo.jar", "log4j-core-2.14.1.jar"},
		result:         crawl.JarNameInsideArchive,
		version:        "2.14.1",
	}, {
		name:           "tarred and gzipped with vulnerable log4j version, multiple . in filename",
		filename:       "foo.bar.tar.gz",
		filesInArchive: []string{"foo.jar", "log4j-core-2.14.1.jar"},
		result:         crawl.JarNameInsideArchive,
		version:        "2.14.1",
	}, {
		name:           "archive with JndiManager class in wrong package",
		filename:       "java.jar",
		filesInArchive: []string{"a/package/with/JndiManager.class"},
		result:         crawl.JndiManagerClassName,
		version:        crawl.UnknownVersion,
	}, {
		name:           "non-log4j archive with JndiManager in the log4j package",
		filename:       "not-log4.jar",
		filesInArchive: []string{"org/apache/logging/log4j/core/net/JndiManager.class"},
		result:         crawl.JndiManagerClassPackageAndName,
		version:        crawl.UnknownVersion,
	}, {
		name:           "vulnerable log4j named jar with JndiManager class",
		filename:       "log4j-core-2.14.1.jar",
		filesInArchive: []string{"org/apache/logging/log4j/core/net/JndiManager.class"},
		result:         crawl.JarName | crawl.JndiManagerClassPackageAndName,
		version:        "2.14.1",
	}, {
		name:           "fixed log4j version with JndiManager class",
		filename:       "log4j-core-2.17.1.jar",
		filesInArchive: []string{"org/apache/logging/log4j/core/net/JndiManager.class"},
		result:         crawl.NothingDetected,
	}, {
		name:           "zip with uppercase log4j inside",
		filename:       "foo.jar",
		filesInArchive: []string{"log4j-core-2.14.1.jAr"},
		result:         crawl.JarNameInsideArchive,
		version:        "2.14.1",
	}, {
		name:           "JndiLookup class name hit",
		filename:       "foo.jar",
		filesInArchive: []string{"a/b/JndiLookup.class"},
		result:         crawl.JndiLookupClassName,
		version:        crawl.UnknownVersion,
	}, {
		name:     "JndiLookup class name and package hit",
		filename: "log4j-core-2.14.1.jar",
		filesInArchive: []string{"org/apache/logging/log4j/core/net/JndiManager.class",
			"org/apache/logging/log4j/core/lookup/JndiLookup.class"},
		result:  crawl.JarName | crawl.JndiLookupClassPackageAndName | crawl.JndiManagerClassPackageAndName,
		version: "2.14.1",
	}} {
		t.Run(tc.name, func(t *testing.T) {
			identifier := crawl.Log4jIdentifier{
				ArchiveWalkers: func(string) (archive.WalkerProvider, int64, bool) {
					return archive.WalkerProviderFromFuncs(func(string) (archive.WalkFn, func() error, error) {
						return func(ctx context.Context, walkFn archive.FileWalkFn) error {
							for _, path := range tc.filesInArchive {
								if _, err := walkFn(ctx, path, 0, bytes.NewReader(emptyZipContent(t))); err != nil {
									return err
								}
							}
							return nil
						}, noopCloser, nil
					}, nil), -1, true
				},
				ArchiveWalkTimeout: time.Second,
				Limiter:            ratelimit.NewUnlimited(),
			}
			result, version, _, err := identifier.Identify(context.Background(), "/path/on/disk/"+tc.filename, tc.filename)
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

func mustWriteTempFile(t *testing.T, name string, content []byte) string {
	t.Helper()
	temp, err := os.CreateTemp(t.TempDir(), name)
	require.NoError(t, err)
	_, err = temp.Write(content)
	require.NoError(t, err)
	require.NoError(t, temp.Close())
	return temp.Name()
}

func emptyZipContent(t *testing.T) []byte {
	var buf bytes.Buffer
	require.NoError(t, zip.NewWriter(&buf).Close())
	return buf.Bytes()
}

func noopCloser() error { return nil }
