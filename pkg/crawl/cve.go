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

package crawl

import (
	"sort"
)

const (
	CVE202145105 = CVEID("CVE-2021-45105")
	CVE202144228 = CVEID("CVE-2021-44228")
	CVE202145046 = CVEID("CVE-2021-45046")
	CVE202144832 = CVEID("CVE-2021-44832")
)

type CVEID string

var cveVersions = []AffectedVersion{
	{
		CVE: CVE202144228,
		FixedAfter: Log4jVersion{
			Major: 2,
			Minor: 16,
			Patch: 0,
		},
		PatchedVersions: []Log4jVersion{
			{
				Major: 2,
				Minor: 12,
				Patch: 2,
			},
			{
				Major: 2,
				Minor: 3,
				Patch: 1,
			},
		},
	},
	{
		CVE: CVE202145046,
		FixedAfter: Log4jVersion{
			Major: 2,
			Minor: 16,
			Patch: 0,
		},
		PatchedVersions: []Log4jVersion{
			{
				Major: 2,
				Minor: 12,
				Patch: 2,
			},
			{
				Major: 2,
				Minor: 3,
				Patch: 1,
			},
		},
	},
	{
		CVE: CVE202145105,
		FixedAfter: Log4jVersion{
			Major: 2,
			Minor: 17,
			Patch: 0,
		},
		PatchedVersions: []Log4jVersion{
			{
				Major: 2,
				Minor: 12,
				Patch: 3,
			},
			{
				Major: 2,
				Minor: 3,
				Patch: 1,
			},
		},
	},
	{
		CVE: CVE202144832,
		FixedAfter: Log4jVersion{
			Major: 2,
			Minor: 17,
			Patch: 1,
		},
		PatchedVersions: []Log4jVersion{
			{
				Major: 2,
				Minor: 12,
				Patch: 4,
			},
			{
				Major: 2,
				Minor: 3,
				Patch: 2,
			},
		},
	},
}

type AffectedVersion struct {
	CVE             CVEID
	FixedAfter      Log4jVersion
	PatchedVersions []Log4jVersion
}

// CVEResolver resolves the CVEs for log4j versions.
type CVEResolver struct {
	// IgnoreCVES contains the IDs of CVEs that will be omitted to CVE results.
	IgnoreCVES []CVEID
}

func (r CVEResolver) CVEs(vs []Log4jVersion) []string {
	cves := make(map[CVEID]struct{})
	for _, v := range vs {
		for _, vulnerability := range cveVersions {
			if v.Major >= vulnerability.FixedAfter.Major && v.Minor >= vulnerability.FixedAfter.Minor && v.Patch >= vulnerability.FixedAfter.Patch {
				continue
			}
			vulnerable := true
			for _, fixedVersion := range vulnerability.PatchedVersions {
				if v.Major == fixedVersion.Major && v.Minor == fixedVersion.Minor && v.Patch >= fixedVersion.Patch {
					vulnerable = false
					break
				}
			}
			if vulnerable && r.included(vulnerability.CVE) {
				cves[vulnerability.CVE] = struct{}{}
			}
		}
	}
	var uniqueCVEs []string
	for cve := range cves {
		uniqueCVEs = append(uniqueCVEs, string(cve))
	}
	sort.Strings(uniqueCVEs)
	return uniqueCVEs
}

func (r CVEResolver) included(cveID CVEID) bool {
	for _, ignoredCVE := range r.IgnoreCVES {
		if cveID == ignoredCVE {
			return false
		}
	}
	return true
}
