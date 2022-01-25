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

package crawl

import (
	"context"
	"fmt"
	"io"
	"os"
	"regexp"
	"strings"

	"go.uber.org/ratelimit"
)

// Crawler crawls filesystems, matching and conditionally processing files.
type Crawler struct {
	Limiter ratelimit.Limiter
	// if non-nil, error output is written to this writer
	ErrorWriter io.Writer
	IgnoreDirs  []*regexp.Regexp
}

type Stats struct {
	// Total number of files scanned.
	FilesScanned uint64 `json:"filesScanned"`
	// Number of paths that were not considered due to "permission denied" errors
	PermissionDeniedCount uint64 `json:"permissionDeniedErrors"`
	// Number of paths that were attempted to be processed but encountered errors.
	PathErrorCount uint64 `json:"pathErrors"`
	// Number of paths that were skipped due to config/size limits
	PathSkippedCount uint64 `json:"pathsSkipped"`
}

// MatchFunc is used to match a file for processing.
// If returning a positive finding, a file will be passed onto the ProcessFunc.
// Returns the finding, if present, along with the version matching as well as the number of
// files skipped and any error encountered.
type MatchFunc func(ctx context.Context, path, filename string) (Finding, Versions, uint64, error)

// ProcessFunc processes the given matched file.
type ProcessFunc func(ctx context.Context, path string, result Finding, version Versions)

// Crawl crawls the provided root directory. Each file is passed to the provided match function, which returns true if
// the path should be processed by the provided process function. On encountering a directory, the path will be compared
// against all IgnoreDirs configured in the Crawler. If any pattern matches, the directory (and all files nested inside
// the directory) will be ignored.
func (c Crawler) Crawl(ctx context.Context, root string, match MatchFunc, process ProcessFunc) (Stats, error) {
	stats := Stats{}
	rootFile, err := os.Lstat(root)
	if err != nil {
		return stats, err
	}
	if !rootFile.IsDir() {
		err = c.processFile(ctx, &stats, root, rootFile.Name(), match, process)
	} else {
		err = c.processDir(ctx, &stats, root, match, process)
	}
	return stats, err
}

func (c Crawler) processDir(ctx context.Context, stats *Stats, path string, match MatchFunc, process ProcessFunc) error {
	dirInfo, err := os.Open(path)
	switch {
	case os.IsPermission(err):
		stats.PermissionDeniedCount++
		return nil
	case os.IsNotExist(err):
		return nil
	case err != nil:
		stats.PathErrorCount++
		if c.ErrorWriter != nil {
			_, _ = fmt.Fprintf(c.ErrorWriter, "Error processing path %s: %v\n", path, err)
		}
		return err
	}
	dirEntries, err := dirInfo.ReadDir(100)
	for err != io.EOF {
		for _, entry := range dirEntries {
			select {
			case <-ctx.Done():
				return ctx.Err()
			default:
			}

			nestedPath := strings.Join([]string{path, entry.Name()}, string(os.PathSeparator))
			if entry.IsDir() {
				if !c.includeDir(nestedPath) {
					continue
				}
				c.Limiter.Take()
				nestedError := c.processDir(ctx, stats, nestedPath, match, process)
				if nestedError != nil {
					return nestedError
				}
			} else if !entry.Type().IsRegular() {
				continue
			} else {
				err = c.processFile(ctx, stats, nestedPath, entry.Name(), match, process)
				if err != nil {
					return err
				}
			}
		}

		dirEntries, err = dirInfo.ReadDir(100)
		if err != nil && err != io.EOF {
			stats.PathErrorCount++
			return nil
		}
	}
	return nil
}

func (c Crawler) processFile(ctx context.Context, stats *Stats, path, name string, match MatchFunc, process ProcessFunc) error {
	stats.FilesScanned++
	matched, version, skipCount, err := match(ctx, path, name)
	stats.PathSkippedCount += skipCount
	if err != nil {
		stats.PathErrorCount++
		if c.ErrorWriter != nil {
			_, _ = fmt.Fprintf(c.ErrorWriter, "Error processing path %s: %v\n", path, err)
		}
		return nil
	}
	if matched == NothingDetected {
		return nil
	}
	process(ctx, path, matched, version)
	return err
}

func (c Crawler) includeDir(path string) bool {
	for _, pattern := range c.IgnoreDirs {
		if pattern.MatchString(path) {
			return false
		}
	}
	return true
}
