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
			firstBytecode, err := java.ReadMethodByteCode(args[0], args[1])
			if err != nil {
				return err
			}
			for _, methodBytecode := range firstBytecode {
				fmt.Printf("%x\n", methodBytecode)
			}

			fmt.Println("\n\n\n\nSecond class")
			secondBytecode, err := java.ReadMethodByteCode(args[2], args[3])
			if err != nil {
				return err
			}
			for _, methodBytecode := range secondBytecode {
				fmt.Printf("%x\n", methodBytecode)
			}

			fmt.Println("\n\n\n\nExact matches")
			for i, firstClassMethodBytecode := range firstBytecode {
				for j, secondClassMethodBytecode := range secondBytecode {
					if bytes.Compare(firstClassMethodBytecode, secondClassMethodBytecode) == 0 {
						fmt.Printf("%x\n", firstClassMethodBytecode)
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

			fmt.Println("\n\n\n\nPartial matches")
			for i, firstClassMethodBytecode := range firstBytecode {
				if len(firstClassMethodBytecode) < 3 {
					// Can't have a partial match unless ther are enough opcodes
					continue
				}
				bestMatchIndex :=  -1
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
					for y > x && z > x && firstClassMethodBytecode[y - 1] == secondClassMethodBytecode[z - 1] {
						y--
						z--
					}
					if x < 1 || y == len(firstClassMethodBytecode) {
						// No match at one or both of the ends
						continue
					}

					matchLength := x + len(firstClassMethodBytecode) - y
					if matchLength > bestMatchPrefixLength + bestMatchSuffixLength {
						bestMatchIndex = j
						bestMatchPrefixLength = x
						bestMatchSuffixLength = len(firstClassMethodBytecode) - y
					}
				}

				if bestMatchIndex > -1 {
					fmt.Printf("%x", firstClassMethodBytecode[:bestMatchPrefixLength])
					for i := bestMatchSuffixLength; i < len(firstClassMethodBytecode); i++ {
						fmt.Printf("_")
					}
					suffixIndex := len(firstClassMethodBytecode) - bestMatchSuffixLength
					fmt.Printf("%x\n", firstClassMethodBytecode[suffixIndex:])
					firstBytecode[i] = nil
					secondBytecode[bestMatchIndex] = nil
				}
			}

			fmt.Println("\n\n\n\nUnmatched bytecode from first class")
			for _, bytecode := range  firstBytecode {
				if bytecode != nil {
					fmt.Printf("%x\n", bytecode)
				}
			}

			fmt.Println("\n\n\n\nUnmatched bytecode from second class")
			for _, bytecode := range  secondBytecode {
				if bytecode != nil {
					fmt.Printf("%x\n", bytecode)
				}
			}
			return nil
		},
	}
	return &cmd
}
