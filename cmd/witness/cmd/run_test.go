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
	"bytes"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"os"
	"testing"

	"github.com/testifysec/witness/cmd/witness/options"
	"github.com/testifysec/witness/pkg/cryptoutil"
)

func Test_runRunRSAKeyPair(t *testing.T) {

	priv, _ := rsakeypair(t)
	keyOptions := options.KeyOptions{
		KeyPath: priv.Name(),
	}

	workingDir := t.TempDir()

	runOptions := options.RunOptions{
		KeyOptions:   keyOptions,
		WorkingDir:   workingDir,
		Attestations: []string{},
		OutFilePath:  workingDir + "outfile.txt",
		StepName:     "teststep",
		RekorServer:  "",
		Tracing:      false,
	}

	args := []string{
		"bash",
		"-c",
		"echo 'test' > test.txt",
	}

	err := runRun(runOptions, args)
	if err != nil {
		t.Errorf("unexpected error: %v", err)
	}

	attestationBytes, err := os.ReadFile(workingDir + "outfile.txt")
	if err != nil {
		t.Error(err)
	}

	if len(attestationBytes) < 1 {
		t.Errorf("Unexpected output size")
	}

	envelopePaths := []string{
		workingDir + "outfile.txt",
	}

	envelopes, err := loadEnvelopesFromDisk(envelopePaths)
	if err != nil {
		t.Errorf("Error loading envelopes from disk: err: %v", err)
	}

	if len(envelopes) != 1 {
		t.Errorf("wrong number of envelopes")
	}
}

func Test_runRunRSACA(t *testing.T) {

	_, intermediates, leafcert, leafkey := fullChain(t)

	workingDir := t.TempDir()

	intermediateNames := []string{}
	for _, intermediate := range intermediates {
		intermediateNames = append(intermediateNames, intermediate.Name())
	}

	keyOptions := options.KeyOptions{
		KeyPath:           leafkey.Name(),
		CertPath:          leafcert.Name(),
		IntermediatePaths: intermediateNames,
	}

	runOptions := options.RunOptions{
		KeyOptions:   keyOptions,
		WorkingDir:   workingDir,
		Attestations: []string{},
		OutFilePath:  workingDir + "outfile.txt",
		StepName:     "teststep",
		RekorServer:  "",
		Tracing:      false,
	}

	args := []string{
		"bash",
		"-c",
		"echo 'test' > test.txt",
	}

	err := runRun(runOptions, args)
	if err != nil {
		t.Errorf("unexpected error: %v", err)
	}

	attestationBytes, err := os.ReadFile(workingDir + "outfile.txt")
	if err != nil {
		t.Error(err)
	}

	if len(attestationBytes) < 1 {
		t.Errorf("Unexpected output size")
	}

	envelopePaths := []string{
		workingDir + "outfile.txt",
	}

	envelopes, err := loadEnvelopesFromDisk(envelopePaths)
	if err != nil {
		t.Errorf("Error loading envelopes from disk: err: %v", err)
	}

	if len(envelopes) != 1 {
		t.Errorf("wrong number of envelopes")
	}

	b, err := os.ReadFile(intermediateNames[0])
	if err != nil {
		t.Errorf("Error reading intermediate cert: %v", err)
	}

	if !bytes.Equal(b, envelopes[0].Envelope.Signatures[0].Intermediates[0]) {
		t.Errorf("Intermediates do not match")
	}

	b, err = os.ReadFile(leafcert.Name())
	if err != nil {
		t.Errorf("Error reading leaf cert: %v", err)
	}

	if !bytes.Equal(b, envelopes[0].Envelope.Signatures[0].Certificate) {
		t.Errorf("Leaf cert does not match")
	}

}

func createTestRSAKey() (cryptoutil.Signer, cryptoutil.Verifier, []byte, []byte, error) {
	privKey, err := rsa.GenerateKey(rand.Reader, keybits)
	if err != nil {
		return nil, nil, nil, nil, err
	}

	signer := cryptoutil.NewRSASigner(privKey, crypto.SHA256)
	verifier := cryptoutil.NewRSAVerifier(&privKey.PublicKey, crypto.SHA256)
	keyBytes, err := x509.MarshalPKIXPublicKey(&privKey.PublicKey)
	if err != nil {
		return nil, nil, nil, nil, err
	}

	pemBytes := pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: keyBytes})
	if err != nil {
		return nil, nil, nil, nil, err
	}

	privKeyBytes := pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(privKey)})
	if err != nil {
		return nil, nil, nil, nil, err
	}

	return signer, verifier, pemBytes, privKeyBytes, nil
}
