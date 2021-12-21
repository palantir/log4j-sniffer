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

package scan

import (
	"encoding/json"
	"fmt"
	"io"

	"github.com/palantir/log4j-sniffer/pkg/crawl"
)

type SummaryJSON struct {
	crawl.Stats
	NumImpactedFiles int64 `json:"numImpactedFiles"`
}

func WriteSummary(w io.Writer, config Config, crawlStats crawl.Stats, count int64) error {
	cveInfo := "CVE-2021-45046"
	if !config.DisableCVE45105 {
		cveInfo += " or CVE-2021-45105"
	}

	var output string
	if config.OutputJSON {
		jsonBytes, err := json.Marshal(SummaryJSON{
			Stats:            crawlStats,
			NumImpactedFiles: count,
		})
		if err != nil {
			return err
		}
		output = string(jsonBytes)
	} else {
		if count > 0 {
			output = fmt.Sprintf("Files affected by %s detected: %d file(s) impacted by %s", cveInfo, count, cveInfo)
		} else {
			output = fmt.Sprintf("No files affected by %s detected", cveInfo)
		}
		output += fmt.Sprintf("\n%d total files scanned, skipped %d paths due to permission denied errors, encountered %d errors processing paths", crawlStats.FilesScanned, crawlStats.PermissionDeniedCount, crawlStats.PathErrorCount)
	}
	_, err := fmt.Fprintln(w, output)
	if err != nil {
		return err
	}
	return nil
}
