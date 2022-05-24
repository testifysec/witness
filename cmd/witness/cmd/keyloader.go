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

	"github.com/testifysec/witness/cmd/witness/options"
	"github.com/testifysec/witness/pkg/cryptoutil"
	"github.com/testifysec/witness/pkg/signer/file"
	"github.com/testifysec/witness/pkg/signer/fulcio"
	"github.com/testifysec/witness/pkg/signer/spiffe"
)

func loadSigners(ctx context.Context, ko options.KeyOptions, so options.SpiffeOptions) ([]cryptoutil.Signer, []error) {
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
	if so.Address != "" {
		spiffeSigner, err := spiffe.Signer(ctx, so.Address)
		if err != nil {
			err := fmt.Errorf("failed to create signer from spiffe: %w", err)
			errors = append(errors, err)
		} else {
			signers = append(signers, spiffeSigner)
		}
	}

	return signers, errors
}
