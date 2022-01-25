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
	"context"

	"github.com/palantir/log4j-sniffer/pkg/crawl"
	"github.com/palantir/log4j-sniffer/pkg/log"
)

// Deleter will delete files containing vulnerable findings given they match certain criteria.
type Deleter struct {
	Logger        log.Logger
	FilepathMatch func(filepath string) (bool, error)
	FindingMatch  func(finding crawl.Finding) bool
	DryRun        bool
	Delete        func(filepath string) error
}

// Process a finding and delete it if it is eligible for deletion given certain configuration criteria.
//
// If the filepath and detailed finding both match for a given crawl.Path then a file is eligible for deletion.
// In this case, Process will always return false to state that this file should no longer exist and that inspecting
// this file for more findings should  not be undertaken.
//
// When Deleter.DryRun is true then a line will be logged stating that the file would be deleted.
// When Deleter.Delete is false, then the configured function Delete will be called to delete the file.
func (d Deleter) Process(ctx context.Context, path crawl.Path, finding crawl.Finding, _ crawl.Versions) bool {
	if len(path) == 0 {
		return true
	}
	match, err := d.FilepathMatch(path[0])
	if err != nil {
		d.Logger.Error("Error matching file %s: %s", path[0], err)
		return true
	}
	if !match {
		return true
	}
	if !d.FindingMatch(finding) {
		return true
	}
	if d.DryRun {
		d.Logger.Info("Dry-run: would delete %s", path[0])
		return false
	}
	if err := d.Delete(path[0]); err != nil {
		d.Logger.Error("Error deleting file %s: %s", path[0], err.Error())
	} else {
		d.Logger.Info("Deleted file %s", path[0])
	}
	return false
}
