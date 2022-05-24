// Copyright 2021 The Witness Contributors
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
	"context"
	"fmt"
	"os"

	"github.com/spf13/cobra"
	"github.com/testifysec/witness/cmd/witness/options"
	witness "github.com/testifysec/witness/pkg"
	"github.com/testifysec/witness/pkg/log"
)

func SignCmd() *cobra.Command {
	so := options.SignOptions{}
	cmd := &cobra.Command{
		Use:               "sign [file]",
		Short:             "Signs a file",
		Long:              "Signs a file with the provided key source and outputs the signed file to the specified destination",
		SilenceErrors:     true,
		SilenceUsage:      true,
		DisableAutoGenTag: true,
		RunE: func(cmd *cobra.Command, args []string) error {
			return runSign(so)
		},
	}

	so.AddFlags(cmd)
	return cmd
}

//todo: this logic should be broken out and moved to pkg/
//we need to abstract where keys are coming from, etc
func runSign(so options.SignOptions) error {
	ctx := context.Background()
	if so.KeyOptions.FulcioURL != "" {
		err := fmt.Errorf("fulcio url is not supported for signing")
		return err
	}

	signers, errors := loadSigners(ctx, so.KeyOptions, so.SpiffeOptions)
	if len(errors) > 0 {
		for _, err := range errors {
			log.Error(err)
		}
		return fmt.Errorf("failed to load signers")
	}

	if len(signers) > 1 {
		log.Error("only one signer is supported")
		return fmt.Errorf("only one signer is supported")
	}

	if len(signers) == 0 {
		log.Error("no signers found")
		return fmt.Errorf("no signers found")
	}

	signer := signers[0]

	inFile, err := os.Open(so.InFilePath)
	if err != nil {
		return fmt.Errorf("failed to open file to sign: %v", err)
	}

	outFile, err := loadOutfile(so.OutFilePath)
	if err != nil {
		return err
	}

	defer outFile.Close()
	return witness.Sign(inFile, so.DataType, outFile, signer)
}
