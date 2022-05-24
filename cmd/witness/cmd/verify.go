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
	"crypto"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"github.com/testifysec/witness/pkg/sink"
	"io"
	"os"
	"strings"

	"github.com/spf13/cobra"
	"github.com/testifysec/witness/cmd/witness/options"
	witness "github.com/testifysec/witness/pkg"
	"github.com/testifysec/witness/pkg/cryptoutil"
	"github.com/testifysec/witness/pkg/dsse"
	"github.com/testifysec/witness/pkg/log"
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

const (
	MAX_DEPTH = 4
)

//todo: this logic should be broken out and moved to pkg/
//we need to abstract where keys are coming from, etc
func runVerify(vo options.VerifyOptions, args []string) error {
	if vo.KeyPath == "" && len(vo.CAPaths) == 0 {
		return fmt.Errorf("must suply public key or ca paths")
	}

	var verifier cryptoutil.Verifier

	if vo.KeyPath != "" {
		keyFile, err := os.Open(vo.KeyPath)
		if err != nil {
			return fmt.Errorf("failed to open key file: %w", err)
		}
		defer keyFile.Close()

		verifier, err = cryptoutil.NewVerifierFromReader(keyFile)
		if err != nil {
			return fmt.Errorf("failed to create verifier: %w", err)
		}

	}

	inFile, err := os.Open(vo.PolicyFilePath)
	if err != nil {
		return fmt.Errorf("failed to open file to sign: %v", err)
	}

	defer inFile.Close()
	policyEnvelope := dsse.Envelope{}
	decoder := json.NewDecoder(inFile)
	if err := decoder.Decode(&policyEnvelope); err != nil {
		return fmt.Errorf("could not unmarshal policy envelope: %w", err)
	}

	fetchedEnvelopes := make([]witness.CollectionEnvelope, 0)
	if len(vo.AttestationDigests) > 0 {
		for _, d := range vo.AttestationDigests {
			parts := strings.Split(d, " ")
			if len(parts) == 1 {
				return fmt.Errorf("failed to parse attestation digests: %v", err)
			}

			digest := parts[0]
			alg := parts[1]

			archivist, err := sink.NewArchivist(
				vo.CollectorOptions.Server,
				vo.CollectorOptions.CACertPath,
				vo.CollectorOptions.ClientCert,
				vo.CollectorOptions.ClientKey,
				vo.SpiffeOptions.Address,
				vo.SpiffeOptions.TrustedServerId,
			)
			if err != nil {
				return fmt.Errorf("failed connecting to upstream archivist: %v", err)
			}

			resp, err := archivist.GetBySubjectDigestRequest(context.Background(), alg, digest)
			if err != nil {
				return fmt.Errorf("failed requesting attestations by digest: %v", err)
			}

			for _, e := range resp {
				var envelope dsse.Envelope
				attBytes := []byte(e)
				err := json.Unmarshal(attBytes, &envelope)
				if err != nil {
					return fmt.Errorf("failed to retrieve dsse for subject: %v", err)
				}
				fetchedEnvelopes = append(fetchedEnvelopes, witness.CollectionEnvelope{
					Envelope:  envelope,
					Reference: fmt.Sprintf("sha256:%x  %s", sha256.Sum256(attBytes), ""),
				})
			}
		}
	} else {
		fetchedEnvelopes, err = loadEnvelopesFromDisk(vo.AttestationFilePaths)
		if err != nil {
			return fmt.Errorf("failed to load attestation files: %w", err)
		}
	}

	verifiedEvidence := []witness.CollectionEnvelope{}

	if vo.RekorServer != "" {

		artifactDigestSet, err := cryptoutil.CalculateDigestSetFromFile(vo.ArtifactFilePath, []crypto.Hash{crypto.SHA256})
		if err != nil {
			return fmt.Errorf("failed to calculate artifact file's hash: %w", err)
		}

		rc, err := rekor.New(vo.RekorServer)
		if err != nil {
			return fmt.Errorf("failed to get initialize Rekor client: %w", err)
		}

		digestSets := []cryptoutil.DigestSet{}
		digestSets = append(digestSets, artifactDigestSet)

		verifiers := []cryptoutil.Verifier{}
		verifiers = append(verifiers, verifier)

		evidence, err := rc.FindEvidence(digestSets, policyEnvelope, verifiers, fetchedEnvelopes, MAX_DEPTH)
		if err != nil {
			return fmt.Errorf("failed to find evidence: %w", err)
		}

		verifiedEvidence = append(verifiedEvidence, evidence...)
	}

	if vo.RekorServer == "" {
		verifiedEvidence, err = witness.Verify(
			policyEnvelope,
			[]cryptoutil.Verifier{verifier},
			witness.VerifyWithCollectionEnvelopes(fetchedEnvelopes),
		)
		if err != nil {
			return fmt.Errorf("failed to verify policy: %w", err)

		}
	}

	log.Info("Verification succeeded")
	log.Info("Evidence:")
	for i, e := range verifiedEvidence {
		log.Info(fmt.Sprintf("%d: %s", i, e.Reference))
	}
	return nil

}

func loadEnvelopesFromDisk(paths []string) ([]witness.CollectionEnvelope, error) {
	envelopes := make([]witness.CollectionEnvelope, 0)
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

		h := sha256.Sum256(fileBytes)

		collectionEnv := witness.CollectionEnvelope{
			Envelope:  env,
			Reference: fmt.Sprintf("sha256:%x  %s", h, path),
		}

		envelopes = append(envelopes, collectionEnv)
	}

	return envelopes, nil
}
