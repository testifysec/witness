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
	"crypto"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"io"
	"os"

	"github.com/spf13/cobra"
	"github.com/testifysec/witness/cmd/options"
	witness "github.com/testifysec/witness/pkg"
	"github.com/testifysec/witness/pkg/cryptoutil"
	"github.com/testifysec/witness/pkg/dsse"
	"github.com/testifysec/witness/pkg/intoto"
	"github.com/testifysec/witness/pkg/policy"
	"github.com/testifysec/witness/pkg/rekor"
)

func VerifyCmd() *cobra.Command {
	vo := options.VerifyOptions{}
	cmd := &cobra.Command{
		Use:               "verify",
		Short:             "Verifies a witness policy",
		Long:              "Verifies a policy provided key source and exits with code 0 if verification succeeds",
		SilenceErrors:     true,
		SilenceUsage:      true,
		DisableAutoGenTag: true,
		RunE: func(cmd *cobra.Command, args []string) error {
			return runVerify(vo, args)
		},
	}
	vo.AddFlags(cmd)
	return cmd
}

//todo: this logic should be broken out and moved to pkg/
//we need to abstract where keys are coming from, etc
func runVerify(vo options.VerifyOptions, args []string) error {
	keyFile, err := os.Open(vo.KeyPath)
	if err != nil {
		return fmt.Errorf("failed to open key file: %v", err)
	}

	defer keyFile.Close()
	verifier, err := cryptoutil.NewVerifierFromReader(keyFile)
	if err != nil {
		return fmt.Errorf("failed to load key: %v", err)
	}

	inFile, err := os.Open(vo.PolicyFilePath)
	if err != nil {
		return fmt.Errorf("failed to open file to sign: %v", err)
	}

	defer inFile.Close()
	policyEnvelope, err := witness.VerifySignature(inFile, verifier)
	if err != nil {
		return fmt.Errorf("failed to verify policy: %v", err)
	}

	pol := policy.Policy{}
	err = json.Unmarshal(policyEnvelope.Payload, &pol)
	if err != nil {
		return fmt.Errorf("failed to parse policy: %v", err)
	}

	envelopes := make([]dsse.Envelope, 0)
	diskEnvs, err := loadEnvelopesFromDisk(vo.AttestationFilePaths)
	if err != nil {
		return fmt.Errorf("failed to load attestation files: %w", err)
	}

	envelopes = append(envelopes, diskEnvs...)
	if vo.RekorServer != "" {
		artifactDigestSet, err := cryptoutil.CalculateDigestSetFromFile(vo.ArtifactFilePath, []crypto.Hash{crypto.SHA256})
		if err != nil {
			return fmt.Errorf("failed to calculate artifact file's hash: %w", err)
		}

		rekorEnvs, err := loadEnvelopesFromRekor(vo.RekorServer, artifactDigestSet)
		if err != nil {
			return err
		}

		envelopes = append(envelopes, rekorEnvs...)
	}

	pubkeysById, err := pol.PublicKeyVerifiers()
	if err != nil {
		return fmt.Errorf("failed to get public keys from policy: %w", err)
	}

	pubkeys := make([]cryptoutil.Verifier, 0)
	for _, pubkey := range pubkeysById {
		pubkeys = append(pubkeys, pubkey)
	}

	trustBundlesById, err := pol.TrustBundles()
	if err != nil {
		return fmt.Errorf("failed to load policy trust bundles: %w", err)
	}

	roots := make([]*x509.Certificate, 0)
	intermediates := make([]*x509.Certificate, 0)
	for _, trustBundle := range trustBundlesById {
		roots = append(roots, trustBundle.Root)
		intermediates = append(intermediates, intermediates...)
	}

	verifiedStatements := make([]policy.VerifiedStatement, 0)
	for _, env := range envelopes {
		passedVerifiers, err := env.Verify(dsse.WithVerifiers(pubkeys), dsse.WithRoots(roots), dsse.WithIntermediates(intermediates))
		if err != nil {
			continue
		}

		statement := intoto.Statement{}
		if err := json.Unmarshal(env.Payload, &statement); err != nil {
			continue
		}

		verifiedStatements = append(verifiedStatements, policy.VerifiedStatement{
			Statement: statement,
			Verifiers: passedVerifiers,
		})
	}

	return pol.Verify(verifiedStatements)
}

func loadEnvelopesFromDisk(paths []string) ([]dsse.Envelope, error) {
	envelopes := make([]dsse.Envelope, 0)
	for _, path := range paths {
		file, err := os.Open(path)
		if err != nil {
			return nil, err
		}

		defer file.Close()
		fileBytes, err := io.ReadAll(file)
		if err != nil {
			continue
		}

		env := dsse.Envelope{}
		if err := json.Unmarshal(fileBytes, &env); err != nil {
			continue
		}
		envelopes = append(envelopes, env)
	}

	return envelopes, nil
}

func loadEnvelopesFromRekor(rekorServer string, artifactDigestSet cryptoutil.DigestSet) ([]dsse.Envelope, error) {
	envelopes := make([]dsse.Envelope, 0)
	rc, err := rekor.New(rekorServer)
	if err != nil {
		return nil, fmt.Errorf("failed to get initialize Rekor client: %w", err)
	}

	entries, err := rc.FindEntriesBySubject(artifactDigestSet)
	if err != nil {
		return nil, fmt.Errorf("failed to find any entries in rekor: %w", err)
	}

	for _, entry := range entries {
		env, err := rekor.ParseEnvelopeFromEntry(entry)
		if err != nil {
			return nil, fmt.Errorf("failed to parse dsse envelope from rekor entry: %w", err)
		}

		envelopes = append(envelopes, env)
	}

	return envelopes, nil
}
