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
	"context"
	"fmt"

	"github.com/testifysec/go-witness/cryptoutil"
	"github.com/testifysec/go-witness/signer/file"
	"github.com/testifysec/go-witness/signer/fulcio"
	"github.com/testifysec/go-witness/signer/spiffe"
	"github.com/testifysec/witness/options"
)

func loadSigners(ctx context.Context, ko options.KeyOptions, args []string) ([]cryptoutil.Signer, []error) {
	signers := []cryptoutil.Signer{}
	errors := []error{}

	//Load key from fulcio
	if ko.FulcioURL != "" {
		fulcioSigner, err := fulcio.Signer(ctx, ko.FulcioURL, ko.OIDCClientID, ko.OIDCIssuer)
		if err != nil {
			err := fmt.Errorf("failed to create signer from Fulcio: %w", err)
			errors = append(errors, err)
		} else {
			signers = append(signers, fulcioSigner)
		}
	}

	//Load key from file
	if ko.KeyPath != "" {
		fileSigner, err := file.Signer(ctx, ko.KeyPath, ko.CertPath, ko.IntermediatePaths)
		if err != nil {
			err := fmt.Errorf("failed to create signer from file: %w", err)
			errors = append(errors, err)
		} else {
			signers = append(signers, fileSigner)
		}
	}

	//Load key from spire agent
	if ko.SpiffePath != "" && !ko.DelegatedIdentity {
		spiffeSigner, err := spiffe.Signer(ctx, ko.SpiffePath)
		if err != nil {
			err := fmt.Errorf("failed to create signer from spiffe: %w", err)
			errors = append(errors, err)
		} else {
			signers = append(signers, spiffeSigner)
		}
	}

	if ko.DelegatedIdentity && ko.SpiffePath != "" {
		spiffeSigner, err := spiffe.DelgatedSigner(ctx, ko.SpiffePath+".admin", args[0])
		if err != nil {
			err := fmt.Errorf("failed to create delegated signer from spiffe: %w", err)
			errors = append(errors, err)
		} else {
			signers = append(signers, spiffeSigner)
		}
	}

	return signers, errors
}
