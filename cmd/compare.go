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
	"bytes"
	"fmt"
	"sort"

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
			_, _ = fmt.Fprintf(cmd.OutOrStdout(),"First class method bytecode (hex)\n")
			firstBytecode, err := java.ReadMethodByteCode(args[0], args[1])
			if err != nil {
				return err
			}
			for _, methodBytecode := range firstBytecode {
				fmt.Printf("%x\n", methodBytecode)
			}

			_, _ = fmt.Fprintf(cmd.OutOrStdout(),"\n\n\n\nSecond class method bytecode (hex)\n")
			secondBytecode, err := java.ReadMethodByteCode(args[2], args[3])
			if err != nil {
				return err
			}
			for _, methodBytecode := range secondBytecode {
				_, _ = fmt.Fprintf(cmd.OutOrStdout(),"%x\n", methodBytecode)
			}

			_, _ = fmt.Fprintf(cmd.OutOrStdout(),"\n\n\n\nExact matches\n")
			for i, firstClassMethodBytecode := range firstBytecode {
				for j, secondClassMethodBytecode := range secondBytecode {
					if bytes.Compare(firstClassMethodBytecode, secondClassMethodBytecode) == 0 {
						_, _ = fmt.Fprintf(cmd.OutOrStdout(),"%x\n", firstClassMethodBytecode)
						firstBytecode[i] = nil
						secondBytecode[j] = nil
					}
				}
			}

			sort.SliceStable(firstBytecode, func(i, j int) bool {
				return len(firstBytecode[i]) > len(firstBytecode[j])
			})
			sort.SliceStable(secondBytecode, func(i, j int) bool {
				return len(secondBytecode[i]) > len(secondBytecode[j])
			})

			_, _ = fmt.Fprintf(cmd.OutOrStdout(),"\n\n\n\nPartial matches\n")
			for i, firstClassMethodBytecode := range firstBytecode {
				if len(firstClassMethodBytecode) < 3 {
					// Can't have a partial match unless there are enough opcodes
					continue
				}
				bestMatchIndex := -1
				bestMatchPrefixLength := 0
				bestMatchSuffixLength := 0
				for j, secondClassMethodBytecode := range secondBytecode {
					if len(secondClassMethodBytecode) < 3 {
						continue
					}
					x := 0
					y := len(firstClassMethodBytecode)
					z := len(secondClassMethodBytecode)
					for x < len(firstClassMethodBytecode) && x < len(secondClassMethodBytecode) && firstClassMethodBytecode[x] == secondClassMethodBytecode[x] {
						x++
					}
					for y > x && z > x && firstClassMethodBytecode[y-1] == secondClassMethodBytecode[z-1] {
						y--
						z--
					}
					if x < 1 || y == len(firstClassMethodBytecode) {
						// No match at one or both of the ends
						continue
					}

					matchLength := x + len(firstClassMethodBytecode) - y
					if matchLength > bestMatchPrefixLength+bestMatchSuffixLength {
						bestMatchIndex = j
						bestMatchPrefixLength = x
						bestMatchSuffixLength = len(firstClassMethodBytecode) - y
					}
				}

				if bestMatchIndex > -1 {
					_, _ = fmt.Fprintf(cmd.OutOrStdout(),"%x", firstClassMethodBytecode[:bestMatchPrefixLength])
					for i := bestMatchSuffixLength; i < len(firstClassMethodBytecode); i++ {
						_, _ = fmt.Fprintf(cmd.OutOrStdout(),"_")
					}
					suffixIndex := len(firstClassMethodBytecode) - bestMatchSuffixLength
					_, _ = fmt.Fprintf(cmd.OutOrStdout(),"%x\n", firstClassMethodBytecode[suffixIndex:])
					firstBytecode[i] = nil
					secondBytecode[bestMatchIndex] = nil
				}
			}

			_, _ = fmt.Fprintf(cmd.OutOrStdout(),"\n\n\n\nUnmatched bytecode from first class\n")
			for _, bytecode := range firstBytecode {
				if bytecode != nil {
					_, _ = fmt.Fprintf(cmd.OutOrStdout(),"%x\n", bytecode)
				}
			}

			_, _ = fmt.Fprintf(cmd.OutOrStdout(),"\n\n\n\nUnmatched bytecode from second class\n")
			for _, bytecode := range secondBytecode {
				if bytecode != nil {
					_, _ = fmt.Fprintf(cmd.OutOrStdout(),"%x\n", bytecode)
				}
			}
			return nil
		},
	}
	return &cmd
}
