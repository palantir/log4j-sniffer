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
	"fmt"

	"github.com/palantir/log4j-sniffer/pkg/java"
	"github.com/palantir/log4j-sniffer/pkg/metrics"
	"github.com/palantir/witchcraft-go-logging/wlog/svclog/svc1log"
	"github.com/spf13/cobra"
)

func compareCmd() *cobra.Command {
	cmd := cobra.Command{
		Use:   "compare <source_jar> <class> <target_jar> <class>",
		Args:  cobra.ExactArgs(4),
		Short: "Compares two classes and outputs common parts",
		Long: `Compares the classes specified within source_jar and target_jar.
Outputs the parts the jars have in common in order to build signatures for matching.
The class names must be fully qualified and not end with .class.
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
			bytecode, err := java.ReadMethodByteCode(args[0], args[1])
			if err != nil {
				return err
			}
			for _, methodBytecode := range bytecode {
				fmt.Printf("%x\n", methodBytecode)
			}

			fmt.Println("\n\n\n\nSecond class")
			bytecode, err = java.ReadMethodByteCode(args[2], args[3])
			if err != nil {
				return err
			}
			for _, methodBytecode := range bytecode {
				fmt.Printf("%x\n", methodBytecode)
			}
			return nil
		},
	}
	return &cmd
}
