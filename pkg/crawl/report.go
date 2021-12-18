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
	"sort"

	"github.com/palantir/witchcraft-go-logging/wlog/svclog/svc1log"
)

type Reporter struct {
	count int64
}

// Collect increments the count of number of calls to Reporter.Collect and logs the path of the vulnerable file to disk.
func (r *Reporter) Collect(ctx context.Context, path string, d fs.DirEntry, result Finding, versionSet Versions) {
	versions := sortVersions(versionSet)
	r.count++
	var filenameParam svc1log.Param
	if result&JarName > 0 {
		filenameParam = svc1log.SafeParam("filename", d.Name())
	} else {
		filenameParam = svc1log.UnsafeParam("filename", d.Name())
	}
	svc1log.FromContext(ctx).Info("CVE-2021-45046 detected",
		svc1log.SafeParam("classNameMatched", result&ClassName > 0),
		svc1log.SafeParam("jarNameMatched", result&JarName > 0),
		svc1log.SafeParam("jarNameInsideArchiveMatched", result&JarNameInsideArchive > 0),
		svc1log.SafeParam("classPackageAndNameMatched", result&ClassPackageAndName > 0),
		filenameParam,
		svc1log.UnsafeParam("path", path),
		svc1log.UnsafeParam("log4jVersions", versions))
}

func sortVersions(versions Versions) []string {
	var out []string
	for v := range versions {
		out = append(out, v)
	}
	// N.B. Lexical sort will mess with base-10 versions, but it's better than random.
	sort.Strings(out)
	return out
}

// Count returns the number of times that Collect has been called
func (r Reporter) Count() int64 {
	return r.count
}
