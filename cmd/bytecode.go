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
	"github.com/palantir/log4j-sniffer/pkg/metrics"
	"github.com/palantir/witchcraft-go-logging/wlog/svclog/svc1log"
	"github.com/spf13/cobra"
)

func bytecodeCmd() *cobra.Command {
	var className string
	cmd := cobra.Command{
		Use:   "identify <root>",
		Args:  cobra.ExactArgs(1),
		Short: "Produces hashes to identify a class file within a JAR",
		Long: `Produces hashes to identify a class file within a JAR.
The entire class is hashed to allow for matching against the exact version.
The bytecode opcodes making up the methods are hashed, for matching versions
with modifications.
Use the class-name option to change which class is analysed within the JAR.
`,
		RunE: func(cmd *cobra.Command, args []string) error {
			ctx, closeLogger := contextWithDefaultLogger()
			defer func() {
				metrics.Flush(ctx)
				if err := closeLogger(); err != nil {
					svc1log.FromContext(ctx).Error("Error closing logger",
						svc1log.Stacktrace(err))
				}
			}()
			return nil
		},
	}
	cmd.Flags().StringVar(&className, "class-name", "org.apache.logging.log4j.core.net.JndiManager.class", `Specify the full class name and package to scan.
Defaults to the log4j JdniManager class.`)
	return &cmd
}
