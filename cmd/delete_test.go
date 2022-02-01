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

package cmd

import (
	"bytes"
	"io"
	"io/fs"
	"os"
	"os/user"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestDeleteCmd(t *testing.T) {
	t.Run("errors when no filepath-owner provided and skip-owner-check not set", func(t *testing.T) {
		cmd := deleteCmd()
		cmd.SetArgs([]string{"path"})
		cmd.SetOut(io.Discard)
		var err bytes.Buffer
		cmd.SetErr(&err)
		require.Error(t, cmd.Execute())
		assert.Equal(t, err.String(), "Error: at least one --filepath-owner value must be provided or --skip-owner-check must be set\n")
	})

	t.Run("errors when filepath-owner and skip-owner-check both provided", func(t *testing.T) {
		cmd := deleteCmd()
		cmd.SetArgs([]string{"path", "--filepath-owner", "foo", "--skip-owner-check"})
		cmd.SetOut(io.Discard)
		var err bytes.Buffer
		cmd.SetErr(&err)
		require.Error(t, cmd.Execute())
		assert.Equal(t, err.String(), "Error: --filepath-owner and --skip-owner-check cannot be used together\n")
	})

	t.Run("errors when invalid findings match values provided", func(t *testing.T) {
		cmd := deleteCmd()
		cmd.SetArgs([]string{"path", "--filepath-owner", "foo:bar", "--finding-match", "jarName", "--finding-match", "🧨"})
		cmd.SetOut(io.Discard)
		var err bytes.Buffer
		cmd.SetErr(&err)
		require.Error(t, cmd.Execute())
		assert.Equal(t, "Error: invalid finding-match 🧨, supported values are ClassBytecodeInstructionMd5, ClassBytecodePartialMatch, ClassFileMd5, JarFileObfuscated, JarName, JarNameInsideArchive, JndiLookupClassName, JndiLookupClassPackageAndName, JndiManagerClassName, JndiManagerClassPackageAndName\n", err.String())
	})

	t.Run("errors when invalid filepath-owner provided", func(t *testing.T) {
		cmd := deleteCmd()
		cmd.SetArgs([]string{"foo", "--filepath-owner", "foo"})
		cmd.SetOut(io.Discard)
		cmd.SetErr(io.Discard)
		require.EqualError(t, cmd.Execute(), `invalid filepath-owner, must contain 2 colon-separated segments but got "foo"`)
	})

	t.Run("errors when one of many filepath-owner provided is invalid", func(t *testing.T) {
		cmd := deleteCmd()
		cmd.SetArgs([]string{"foo", "--filepath-owner", "foo:bar", "--filepath-owner", "baz"})
		cmd.SetOut(io.Discard)
		cmd.SetErr(io.Discard)
		require.EqualError(t, cmd.Execute(), `invalid filepath-owner, must contain 2 colon-separated segments but got "baz"`)
	})

	t.Run("errors when filepath-owner pattern cannot be created", func(t *testing.T) {
		cmd := deleteCmd()
		cmd.SetArgs([]string{"foo", "--filepath-owner", "**:bar"})
		cmd.SetOut(io.Discard)
		cmd.SetErr(io.Discard)
		err := cmd.Execute()
		require.Error(t, err)
		assert.Contains(t, err.Error(), `error compiling pattern for filepath-owner **:bar`)
	})

	t.Run("Runs deletions in dry-mode by default", func(t *testing.T) {
		examples := []string{
			"multiple_bad_versions/log4j-core-2.10.0.jar",
			"multiple_bad_versions/log4j-core-2.11.0.jar",
			"renamed_jar_class_file_extensions/not-a-finding.jar",
		}
		dir := setupExamplesDir(t, examples...)
		cmd := deleteCmd()
		current, err := user.Current()
		require.NoError(t, err)
		cmd.SetArgs([]string{dir, "--filepath-owner", dir + ".*:" + current.Username})
		var out bytes.Buffer
		cmd.SetOut(&out)
		require.NoError(t, cmd.Execute())
		assert.Contains(t, out.String(), "[INFO] Dry-run: would delete "+filepath.Join(dir, "multiple_bad_versions/log4j-core-2.10.0.jar"))
		assert.Contains(t, out.String(), "[INFO] Dry-run: would delete "+filepath.Join(dir, "multiple_bad_versions/log4j-core-2.11.0.jar"))
		assert.NotContains(t, out.String(), "[INFO] Dry-run: would delete "+filepath.Join(dir, "renamed_jar_class_file_extensions/not-a-finding.jar"))
	})

	t.Run("Does not delete when finding-match not reached", func(t *testing.T) {
		examples := []string{
			"multiple_bad_versions/log4j-core-2.10.0.jar",
			"multiple_bad_versions/log4j-core-2.11.0.jar",
			"renamed_jar_class_file_extensions/not-a-finding.jar",
		}
		dir := setupExamplesDir(t, examples...)
		cmd := deleteCmd()
		current, err := user.Current()
		require.NoError(t, err)
		cmd.SetArgs([]string{dir, "--filepath-owner", dir + ".*:" + current.Username, "--finding-match", "jarNameInsideArchive"})
		var out bytes.Buffer
		cmd.SetOut(&out)
		require.NoError(t, cmd.Execute())
		_, err = os.Stat(filepath.Join(dir, "multiple_bad_versions/log4j-core-2.10.0.jar"))
		assert.NoError(t, err)
		_, err = os.Stat(filepath.Join(dir, "multiple_bad_versions/log4j-core-2.11.0.jar"))
		assert.NoError(t, err)
		_, err = os.Stat(filepath.Join(dir, "renamed_jar_class_file_extensions/not-a-finding.jar"))
		assert.NoError(t, err)
	})

	t.Run("Deletes findings when dry-run=false with filepath-owner", func(t *testing.T) {
		examples := []string{
			"multiple_bad_versions/log4j-core-2.10.0.jar",
			"multiple_bad_versions/log4j-core-2.11.0.jar",
			"renamed_jar_class_file_extensions/not-a-finding.jar",
		}
		dir := setupExamplesDir(t, examples...)
		cmd := deleteCmd()
		current, err := user.Current()
		require.NoError(t, err)
		cmd.SetArgs([]string{dir, "--dry-run=false", "--filepath-owner", dir + ".*:" + current.Username})
		var out bytes.Buffer
		cmd.SetOut(&out)
		require.NoError(t, cmd.Execute())
		var found []string
		require.NoError(t, filepath.Walk(dir, func(path string, info fs.FileInfo, err error) error {
			if !info.IsDir() {
				found = append(found, path)
			}
			return nil
		}))
		assert.Equal(t, []string{filepath.Join(dir, "renamed_jar_class_file_extensions/not-a-finding.jar")}, found,
			"bad versions should not still be found")
	})

	t.Run("Deletes findings when dry-run=false with skip-owner-check", func(t *testing.T) {
		examples := []string{
			"multiple_bad_versions/log4j-core-2.10.0.jar",
			"multiple_bad_versions/log4j-core-2.11.0.jar",
			"renamed_jar_class_file_extensions/not-a-finding.jar",
		}
		dir := setupExamplesDir(t, examples...)
		cmd := deleteCmd()
		cmd.SetArgs([]string{dir, "--dry-run=false", "--skip-owner-check"})
		var out bytes.Buffer
		cmd.SetOut(&out)
		require.NoError(t, cmd.Execute())
		var found []string
		require.NoError(t, filepath.Walk(dir, func(path string, info fs.FileInfo, err error) error {
			if err != nil {
				return err
			}
			if !info.IsDir() {
				found = append(found, path)
			}
			return nil
		}))
		assert.Equal(t, []string{filepath.Join(dir, "renamed_jar_class_file_extensions/not-a-finding.jar")}, found,
			"bad versions should not still be found")
	})
}

func setupExamplesDir(t *testing.T, names ...string) string {
	dir := t.TempDir()
	for _, name := range names {
		existing, err := os.Open(filepath.Join("../examples", name))
		require.NoError(t, err)
		defer func() { assert.NoError(t, existing.Close()) }()
		newPath := filepath.Join(dir, name)
		dir, _ := filepath.Split(newPath)
		require.NoError(t, os.MkdirAll(dir, 0700))
		new, err := os.Create(newPath)
		require.NoError(t, err)
		defer func() { assert.NoError(t, new.Close()) }()
		_, err = io.Copy(new, existing)
		require.NoError(t, err)
	}
	return dir
}
