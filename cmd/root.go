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

package cmd

import (
	"time"

	"github.com/palantir/pkg/cobracli"
	"github.com/spf13/cobra"
)

var (
	Version               = "unspecified"
	ignoreDirs            []string
	perArchiveTimeout     time.Duration
	nestedArchiveMaxDepth uint
	nestedArchiveMaxSize  uint
	disableCVE45105       bool
	outputJSON            bool
	outputSummary         bool
)

func Execute() int {
	rootCmd := &cobra.Command{
		Use:   "log4j-sniffer",
		Short: "Filesystem crawler to identify jars and java classes",
	}
	rootCmd.AddCommand(crawlCmd())
	rootCmd.AddCommand(identifyCmd())
	rootCmd.AddCommand(compareCmd())
	rootCmd.AddCommand(dockerCmd())
	rootCmd.PersistentFlags().StringSliceVar(&ignoreDirs, "ignore-dir", nil, `Specify directory pattern to ignore. Use multiple times to supply multiple patterns.
Patterns should be relative to the provided root.
e.g. ignore "^/proc" to ignore "/proc" when using a crawl root of "/"`)
	rootCmd.PersistentFlags().DurationVar(&perArchiveTimeout, "per-archive-timeout", 15*time.Minute, `If this duration is exceeded when inspecting an archive, an error will be logged and the crawler will move onto the next file.`)
	rootCmd.PersistentFlags().UintVar(&nestedArchiveMaxSize, "nested-archive-max-size", 5*1024*1024, `The maximum compressed size in bytes of any nested archive that will be unarchived for inspection.
This limit is made a per-depth level.
The overall limit to nested archive size unarchived should be controlled by both the nested-archive-max-size and nested-archive-max-depth.`)
	rootCmd.PersistentFlags().UintVar(&nestedArchiveMaxDepth, "nested-archive-max-depth", 0, `The maximum depth to recurse into nested archives. A max depth of 0 will open up an archive on the filesystem but not any nested archives.`)
	rootCmd.PersistentFlags().BoolVar(&disableCVE45105, "disable-cve-2021-45105-detection", false, `Disable detection of CVE-2021-45105 in versions up to 2.16.0`)
	rootCmd.PersistentFlags().BoolVar(&outputJSON, "json", false, "If true, output will be in JSON format")
	rootCmd.PersistentFlags().BoolVar(&outputSummary, "summary", true, "If true, outputs a summary of all operations once program completes")
	return cobracli.ExecuteWithDefaultParams(rootCmd, cobracli.VersionFlagParam(Version))
}
