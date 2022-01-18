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
	"path/filepath"
	"regexp"

	"go.uber.org/ratelimit"
)

// Crawler crawls filesystems, matching and conditionally processing files.
type Crawler struct {
	Limiter ratelimit.Limiter
	// if non-nil, error output is written to this writer
	ErrorWriter                 io.Writer
	IgnoreDirs                  []*regexp.Regexp
	DirectoryEntriesPerListCall int
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

// ProcessFunc is called on all files encountered when crawling the a filesystem.
type ProcessFunc func(ctx context.Context, path string, filename string) (uint64, error)

// Crawl crawls the provided root directory. Each file is passed to the provided match function, which returns true if
// the path should be processed by the provided process function. On encountering a directory, the path will be compared
// against all IgnoreDirs configured in the Crawler. If any pattern matches, the directory (and all files nested inside
// the directory) will be ignored.
func (c Crawler) Crawl(ctx context.Context, root string, process ProcessFunc) (Stats, error) {
	stats := Stats{}
	rootFile, err := os.Lstat(root)
	if err != nil {
		return stats, err
	}
	if rootFile.IsDir() {
		err = c.processDir(ctx, &stats, root, process)
	} else {
		err = c.processFile(ctx, &stats, root, rootFile.Name(), process)
	}
	return stats, err
}

func (c Crawler) processDir(ctx context.Context, stats *Stats, path string, process ProcessFunc) error {
	dirInfo, err := os.Open(path)
	if err == nil {
		defer func() {
			if cErr := dirInfo.Close(); err == nil && cErr != nil {
				stats.PathErrorCount++
				if c.ErrorWriter != nil {
					_, _ = fmt.Fprintf(c.ErrorWriter, "Error closing file %s: %v\n", path, err)
				}
			}
		}()
	}
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
		return nil
	}

	var dirEntries []os.DirEntry
	for ; err != io.EOF; dirEntries, err = dirInfo.ReadDir(c.DirectoryEntriesPerListCall) {
		if err != nil {
			stats.PathErrorCount++
			if c.ErrorWriter != nil {
				_, _ = fmt.Fprintf(c.ErrorWriter, "Error processing path %s: %v\n", path, err)
			}
			return nil
		}

		for _, entry := range dirEntries {
			select {
			case <-ctx.Done():
				return ctx.Err()
			default:
			}

			nestedPath := filepath.Join(path, entry.Name())
			if entry.IsDir() {
				if !c.includeDir(nestedPath) {
					continue
				}
				c.Limiter.Take()
				if err = c.processDir(ctx, stats, nestedPath, process); err != nil {
					return err
				}
			} else if !entry.Type().IsRegular() {
				continue
			} else {
				if err = c.processFile(ctx, stats, nestedPath, entry.Name(), process); err != nil {
					return err
				}
			}
		}
	}
	return nil
}

func (c Crawler) processFile(ctx context.Context, stats *Stats, path, name string, process ProcessFunc) error {
	stats.FilesScanned++
	skipCount, err := process(ctx, path, name)
	stats.PathSkippedCount += skipCount
	if err != nil {
		stats.PathErrorCount++
		if c.ErrorWriter != nil {
			_, _ = fmt.Fprintf(c.ErrorWriter, "Error processing path %s: %v\n", path, err)
		}
	}
	return nil
}

func (c Crawler) includeDir(path string) bool {
	for _, pattern := range c.IgnoreDirs {
		if pattern.MatchString(path) {
			return false
		}
	}
	return true
}
