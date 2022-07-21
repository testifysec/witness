// Copyright 2022 The Witness Contributors
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package cmd

import (
	"fmt"
	"os"

	"github.com/spf13/cobra"
	"github.com/testifysec/go-witness/log"
	"github.com/testifysec/witness/options"
)

var (
	ro = &options.RootOptions{}
)

func New() *cobra.Command {
	cmd := &cobra.Command{
		Use:               "witness",
		Short:             "Collect and verify attestations about your build environments",
		DisableAutoGenTag: true,
	}

	ro.AddFlags(cmd)
	cmd.AddCommand(SignCmd())
	cmd.AddCommand(VerifyCmd())
	cmd.AddCommand(RunCmd())
	cmd.AddCommand(CompletionCmd())
	cmd.AddCommand(versionCmd())
	cobra.OnInitialize(func() { preRoot(cmd, ro) })
	return cmd
}

func Execute() {
	if err := New().Execute(); err != nil {
		log.Error(err)
		os.Exit(1)
	}
}

func RunPreRoot(ro *options.RootOptions) error {
	logger := newLogger()
	log.SetLogger(logger)
	if err := logger.SetLevel(ro.LogLevel); err != nil {
		logger.l.Fatal(err)
	}

	return nil
}

func preRoot(cmd *cobra.Command, ro *options.RootOptions) {
	logger := newLogger()
	log.SetLogger(logger)
	if err := logger.SetLevel(ro.LogLevel); err != nil {
		logger.l.Fatal(err)
	}

	if err := initConfig(cmd, ro); err != nil {
		logger.l.Fatal(err)
	}
}

func loadOutfile(outFilePath string) (*os.File, error) {
	var err error
	out := os.Stdout
	if outFilePath != "" {
		out, err = os.Create(outFilePath)
		if err != nil {
			return nil, fmt.Errorf("failed to create output file: %v", err)
		}
	}

	return out, err
}
