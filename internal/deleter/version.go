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

package deleter

import (
	"github.com/palantir/log4j-sniffer/pkg/crawl"
)

// CVEResolver resolves Log4jVersions to CVEs
type CVEResolver interface {
	CVEs(vs []crawl.Log4jVersion) []string
}

// VersionMatcher creates a function that will return true only when CVEs are present for a
// set of Versions.
// All Versions will be parsed to extract the log4j version found for them, the valid found
// versions will be resolved to matching CVEs using the CVEResolver.
// If any CVEs are present, the returned bool will be true to represent that the file containing
// the CVEs should be deleted.
func VersionMatcher(cveResolver CVEResolver) func(versions crawl.Versions) bool {
	return func(versions crawl.Versions) bool {
		// ignore fact that there may have been invalid versions
		vs, _ := crawl.ParseLog4jVersions(versions)
		return cveResolver != nil && len(cveResolver.CVEs(vs)) > 0
	}
}
