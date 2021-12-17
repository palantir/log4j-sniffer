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
	"io/fs"
	"regexp"
	"strconv"

	"github.com/palantir/witchcraft-go-logging/wlog/svclog/svc1log"
)

type Reporter struct {
	count int64
}

var versionRegex = regexp.MustCompile(`(?i)^(\d+)\.(\d+)(?:\..*)?$`)

// Collect increments the count of number of calls to Reporter.Collect and logs the path of the vulnerable file to disk.
func (r *Reporter) Collect(ctx context.Context, path string, d fs.DirEntry, result Finding, version string) {
	if !vulnerableVersion(version) {
		return
	}
	r.count++
	var filenameParam svc1log.Param
	if result&JarName > 0 {
		filenameParam = svc1log.SafeParam("filename", d.Name())
	} else {
		filenameParam = svc1log.UnsafeParam("filename", d.Name())
	}
	svc1log.FromContext(ctx).Info("Vulnerable file found",
		svc1log.SafeParam("classNameMatched", result&ClassName > 0),
		svc1log.SafeParam("jarNameMatched", result&JarName > 0),
		svc1log.SafeParam("jarNameInsideArchiveMatched", result&JarNameInsideArchive > 0),
		svc1log.SafeParam("classPackageAndNameMatch", result&ClassPackageAndName > 0),
		filenameParam,
		svc1log.UnsafeParam("path", path))
}

func vulnerableVersion(version string) bool {
	matches := versionRegex.FindStringSubmatch(version)
	if len(matches) == 0 {
		return true
	}
	major, err := strconv.Atoi(matches[1])
	if err != nil {
		// should not be possible due to group of \d+ in regex
		return false
	}
	minor, err := strconv.Atoi(matches[2])
	if err != nil {
		// should not be possible due to group of \d+ in regex
		return true
	}
	return major == 2 && minor < 16
}

// Count returns the number of times that Collect has been called
func (r Reporter) Count() int64 {
	return r.count
}
