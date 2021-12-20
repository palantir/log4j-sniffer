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
	"regexp"

	"github.com/palantir/log4j-sniffer/pkg/scan"
	"github.com/palantir/log4j-sniffer/pkg/scan/docker"
	"github.com/pkg/errors"
	"github.com/spf13/cobra"
)

func dockerCmd() *cobra.Command {
	var (
		imageExtractionDir string
	)
	cmd := cobra.Command{
		Use:   "docker",
		Args:  cobra.NoArgs,
		Short: "Scan docker images for jars vulnerable to CVE-2021-45046.",
		RunE: func(cmd *cobra.Command, args []string) error {
			var ignores []*regexp.Regexp
			for _, pattern := range ignoreDirs {
				compiled, err := regexp.Compile(pattern)
				if err != nil {
					return errors.Wrapf(err, "failed to compile ignore-dir pattern %q", pattern)
				}
				ignores = append(ignores, compiled)
			}

			dockerScanner, err := docker.NewDockerScanner(scan.Config{
				ArchiveListTimeout: perArchiveTimeout,
				ArchiveMaxDepth:    nestedArchiveMaxDepth,
				ArchiveMaxSize:     nestedArchiveMaxSize,
				DisableCVE45105:    disableCVE45105,
				Ignores:            ignores,
				OutputJSON:         outputJSON,
				OutputSummary:      outputSummary,
			}, cmd.OutOrStdout(), cmd.OutOrStderr(), imageExtractionDir)
			if err != nil {
				return err
			}

			_, err = dockerScanner.ScanImages(cmd.Context())
			return err
		},
	}
	cmd.Flags().StringVar(&imageExtractionDir, "image-dir", "", "The directory where docker images should be temporarily extracted to, defaults to system temporary directory")
	return &cmd
}
