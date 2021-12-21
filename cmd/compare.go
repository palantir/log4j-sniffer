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
			comparison, err := java.CompareClasses(args[0], args[1], args[2], args[3])
			if err != nil {
				return err
			}

			_, _ = fmt.Fprintf(cmd.OutOrStdout(), "First class method bytecode (hex)\n")
			printBytecode(cmd, comparison.FirstClassMethodBytecode)
			_, _ = fmt.Fprintf(cmd.OutOrStdout(), "\n\n\n\nSecond class method bytecode (hex)\n")
			printBytecode(cmd, comparison.SecondClassMethodBytecode)
			_, _ = fmt.Fprintf(cmd.OutOrStdout(), "\n\n\n\nExact matches\n")
			printBytecode(cmd, comparison.ExactMatches)
			_, _ = fmt.Fprintf(cmd.OutOrStdout(), "\n\n\n\nPartial matches\n")
			for _, partialMatch := range comparison.PartialMatches {
				_, _ = fmt.Fprintf(cmd.OutOrStdout(), "%x", partialMatch.Prefix)
				for i := 0; i < partialMatch.AmountSkipped; i++ {
					_, _ = fmt.Fprint(cmd.OutOrStdout(), "_")
				}
				_, _ = fmt.Fprintf(cmd.OutOrStdout(), "%x\n", partialMatch.Suffix)
			}
			_, _ = fmt.Fprintf(cmd.OutOrStdout(), "\n\n\n\nUnmatched bytecode from first class\n")
			printBytecode(cmd, comparison.FirstClassUnmatchedBytecode)
			_, _ = fmt.Fprintf(cmd.OutOrStdout(), "\n\n\n\nUnmatched bytecode from second class\n")
			printBytecode(cmd, comparison.SecondClassUnmatchedBytecode)
			return nil
		},
	}
	return &cmd
}

func printBytecode(cmd *cobra.Command, firstBytecode [][]byte) {
	for _, bytecode := range firstBytecode {
		_, _ = fmt.Fprintf(cmd.OutOrStdout(), "%x\n", bytecode)
	}
}
