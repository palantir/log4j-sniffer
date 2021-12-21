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

package docker

import (
	"context"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	dockertypes "github.com/docker/docker/api/types"
	"github.com/docker/docker/client"
	"github.com/google/go-containerregistry/pkg/crane"
	"github.com/google/go-containerregistry/pkg/name"
	"github.com/google/go-containerregistry/pkg/v1/daemon"
	"github.com/mholt/archiver/v3"
	"github.com/palantir/log4j-sniffer/pkg/crawl"
	"github.com/palantir/log4j-sniffer/pkg/scan"
	"github.com/pkg/errors"
)

func ScanImages(ctx context.Context, config scan.Config, stdout, stderr io.Writer, apiClient client.CommonAPIClient, imageExtractionDir string) (int64, error) {
	scanner := scan.NewScannerFromConfig(config, stdout, stderr)

	imageList, err := apiClient.ImageList(ctx, dockertypes.ImageListOptions{})
	if err != nil {
		return 0, errors.Wrap(err, "could not list docker images")
	}

	var stats crawl.Stats
	for _, image := range imageList {
		if len(image.RepoTags) == 0 {
			continue
		}
		scanner.SetImageID(shortImageID(image.ID))
		scanner.SetImageTags(image.RepoTags)
		imageStats, err := scanImage(ctx, scanner, apiClient, image, imageExtractionDir)
		if err != nil {
			// write an error and continue scanning other images if we hit an error with this
			// image
			_, _ = fmt.Fprintln(scanner.ErrorWriter, err.Error())
			continue
		}
		stats.Append(imageStats)
	}

	count := scanner.Count()
	if config.OutputSummary {
		if err := scan.WriteSummary(scanner.OutputWriter, config, stats, count); err != nil {
			return 0, err
		}
	}
	return count, nil
}

func scanImage(ctx context.Context, scanner scan.Scanner, client client.CommonAPIClient, image dockertypes.ImageSummary, imageExtractionDir string) (crawl.Stats, error) {
	ref, err := name.ParseReference(image.RepoTags[0])
	if err != nil {
		return crawl.Stats{}, errors.Wrapf(err, "failed to get image reference")
	}

	img, err := daemon.Image(ref, daemon.WithClient(client), daemon.WithContext(ctx))
	if err != nil {
		return crawl.Stats{}, err
	}

	// create a temporary directory where the docker image tarball can be exported to
	imageTmpDir, err := os.MkdirTemp(imageExtractionDir, fmt.Sprintf("log4j-sniffer-%s", image.ID))
	if err != nil {
		return crawl.Stats{}, errors.Wrap(err, "could not create temporary directory for image")
	}

	outFile, err := os.Create(filepath.Join(imageTmpDir, "image.tar"))
	if err != nil {
		return crawl.Stats{}, err
	}

	defer func() {
		if err := os.RemoveAll(imageTmpDir); err != nil {
			_, _ = fmt.Fprintf(scanner.ErrorWriter, "failed to remove temporary image directory %s\n", imageTmpDir)
		}
	}()

	// flatten all layers into a single layer and export image to tarball
	if err := crane.Export(img, outFile); err != nil {
		return crawl.Stats{}, errors.Wrap(err, "could not export image")
	}

	// this can be removed when we do recursive tars as we can just scan from the
	// imageTmpDir but for now we have to extract the image tarball
	if err := archiver.Unarchive(outFile.Name(), imageTmpDir); err != nil {
		return crawl.Stats{}, errors.Wrap(err, "failed to extract image")
	}

	// remove the image.tar to avoid duplicate matches
	if err := os.Remove(outFile.Name()); err != nil {
		return crawl.Stats{}, err
	}

	// change to the extracted image directory so paths are reported relative to
	// the root of the image
	if err := os.Chdir(imageTmpDir); err != nil {
		return crawl.Stats{}, err
	}

	return scanner.Crawl(ctx, ".", scanner.Identify, scanner.Collect)
}

// returns the first 12 characters of the image ID when split at the : seperator
func shortImageID(id string) string {
	parts := strings.Split(id, ":")
	if len(parts) <= 1 || len(parts[1]) < 12 {
		return id
	}
	return parts[1][0:12]
}
