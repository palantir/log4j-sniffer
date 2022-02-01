// Copyright (c) 2022 Palantir Technologies. All rights reserved.
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
	"errors"
	"fmt"
	"io"
	"os"
	"regexp"
	"strings"

	"github.com/palantir/log4j-sniffer/internal/crawler"
	"github.com/palantir/log4j-sniffer/internal/deleter"
	snifferos "github.com/palantir/log4j-sniffer/internal/os"
	"github.com/palantir/log4j-sniffer/pkg/crawl"
	"github.com/palantir/log4j-sniffer/pkg/log"
	"github.com/spf13/cobra"
)

func deleteCmd() *cobra.Command {
	var (
		cmdCrawlFlags         crawlFlags
		dryRun                bool
		skipOwnerCheck        bool
		directoriesWithOwners []string
		findingsMatches       []string
	)
	cmd := cobra.Command{
		Use: "delete <root>",
		Example: `Delete all findings nested beneath /path/to/dir that are owned by foo and contain findings that match both classFileMd5 and jarFileObfuscated.

log4j-sniffer delete /path/to/dir --dry-run=false --directory-owner ^/path/to/dir/.*:foo --finding-match classFileMd5 --finding-match jarFileObfuscated`,
		Short: "Delete files containing log4j vulnerabilities",
		Long: `Delete files containing log4j vulnerabilities.

Crawl the file system from root, detecting files containing log4j-vulnerabilities and deleting them if they meet certain requirements determined by the command flags.
Root must be provided and can be a single file or directory.

Dry-run mode is enabled by default, where a line will be output to state where a file would be deleted when running not in dry run mode.
It is recommended to run using dry-run mode enabled, checking the logged output and then running with dry-run disabled using the same configuration flags.
Use --dry-run=false to turn off dry-run mode, enabling deletes.

When used on windows, deleting based on file ownership is unsupported and skip-owner-check should be used instead of directory-with-owner.
`,
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			crawlConfig, err := createCrawlConfig(args[0], cmdCrawlFlags)
			if err != nil {
				return err
			}

			if len(directoriesWithOwners) > 0 && skipOwnerCheck {
				return errors.New("--directory-with-owner and --skip-owner-check cannot be used together")
			}
			if len(directoriesWithOwners) == 0 && !skipOwnerCheck {
				return errors.New("at least one --directory-with-owner value must be provided or --skip-owner-check must be set")
			}

			filepathMatch, err := filepathMatcher(skipOwnerCheck, directoriesWithOwners)
			if err != nil {
				return err
			}

			findingMatch, err := minimumFindingMatch(findingsMatches)
			if err != nil {
				return err
			}

			_, err = crawler.Crawl(cmd.Context(), crawlConfig, deleter.Deleter{
				Logger:        logger(cmd, cmdCrawlFlags),
				FilepathMatch: filepathMatch,
				FindingMatch:  findingMatch,
				DryRun:        dryRun,
				Delete:        os.Remove,
			}.Process, cmd.OutOrStdout(), cmd.OutOrStderr())
			return err
		},
	}
	applyCrawlFlags(&cmd, &cmdCrawlFlags)
	cmd.Flags().BoolVar(&dryRun, "dry-run", true, "When true, a line with be output instead of deleting a file. Use --dry-run=false to enable deletion.")
	cmd.Flags().BoolVar(&skipOwnerCheck, "skip-owner-check", false, "When provided, the owner of a file will not be checked before attempting a delete.")
	cmd.Flags().StringSliceVar(&directoriesWithOwners, "directory-with-owner", nil, `Provide a directory pattern and owner template that will be used to check whether a file should be deleted or not when it is deemed to be vulnerable.
Multiple values can be provided and values must be provided in the form directory_pattern:owner_template, where a directory pattern and owner template are colon separated.

When a file is deemed to be vulnerable, the directory containing the file will be matched against all directory patterns.
For all directory matches, the owner template will be expanded against the directory pattern match to resolve to a file owner value that the actual file owner will then be compared against.
Owner templates may use template variables, e.g. $1, $2, $name, that correspond to capture groups in the directory pattern. Please refer to the standard go regexp package documentation at https://pkg.go.dev/regexp#Regexp.Expand for more detailed expanding behaviour.

If no directories match, the file will not be deleted. If any directories match, all matching directory corresponding expanded templated owner values must match against the actual file owner for the file to be deleted.  

Examples:
--directory-owner ^/foo/bar:qux would consider /foo/bar/baz for deletion only if it is owned by qux
--directory-owner ^/foo/bar/:qux and --directory-owner ^/foo/bar/baz:quuz would not consider /foo/bar/baz/corge for deletion if owned by either qux or quuz because both would need to match
--directory-owner ^/foo/(\w+):$1 would consider /foo/bar/baz for deletion only if it is owned by bar 
`)
	cmd.Flags().StringSliceVar(&findingsMatches, "finding-match", nil, `When supplied, any vulnerable finding must contain all values that are provided to finding-match for it to be considered for deletion.
These values are considered on a finding-by-finding basis, i.e. an archive containing two separate vulnerable jars will only be deleted if either of the contained jars matches all finding-match values.

Supported values are as follows:
`+strings.Join(prefixAll(crawl.SupportedVulnerableFindingValues(), "- "), "\n")+`

Example:
--finding-match classFileMd5 and --finding-match jarFileObfuscated would only delete a file containing a vulnerability if the vulnerability contains a class file hash match and an obfuscated jar name.
If a vulnerable finding contained only one of these finding-match values then the file would not be considered for deletion.
`)
	return &cmd
}

func logger(cmd *cobra.Command, cmdCrawlFlags crawlFlags) log.Logger {
	var detailedOutputWriter io.Writer
	var enableTraceLogging bool
	if !cmdCrawlFlags.disableDetailedFindings {
		detailedOutputWriter = cmd.OutOrStdout()
		enableTraceLogging = cmdCrawlFlags.enableTraceLogging
	}
	return log.Logger{
		OutputWriter:       detailedOutputWriter,
		ErrorWriter:        cmd.OutOrStderr(),
		EnableTraceLogging: enableTraceLogging,
	}
}

func minimumFindingMatch(findingsMatches []string) (func(finding crawl.Finding) bool, error) {
	var minimumFindingsRequirement crawl.Finding
	for _, value := range findingsMatches {
		f, err := crawl.FindingOf(value)
		if err != nil {
			return nil, err
		}
		minimumFindingsRequirement |= f
	}
	return func(finding crawl.Finding) bool {
		return crawl.AllFindingsSatisfiedBy(minimumFindingsRequirement, finding)
	}, nil
}

func filepathMatcher(skipOwnerCheck bool, directoriesWithOwners []string) (func(string) (bool, error), error) {
	if skipOwnerCheck {
		return func(string) (bool, error) {
			return true, nil
		}, nil
	}

	var ms []deleter.Matcher
	for _, value := range directoriesWithOwners {
		split := strings.Split(value, ":")
		if len(split) != 2 {
			return nil, fmt.Errorf(`invalid directory-with-owner, must contain 2 colon-separated segments but got %q`, value)
		}
		expr, err := regexp.Compile(split[0])
		if err != nil {
			return nil, fmt.Errorf("error compiling pattern for directory-with-owner %s: %w", value, err)
		}
		ms = append(ms, deleter.TemplatedOwner{
			DirectoryExpression: expr,
			OwnerTemplate:       split[1],
		})
	}

	return (&deleter.FileOwnerMatchers{
		Matchers:     ms,
		ResolveOwner: snifferos.OwnerUsername,
	}).Match, nil
}

func prefixAll(vals []string, prefix string) []string {
	for i := range vals {
		vals[i] = prefix + vals[i]
	}
	return vals
}
