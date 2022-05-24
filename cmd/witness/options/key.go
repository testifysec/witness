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

package options

import "github.com/spf13/cobra"

type KeyOptions struct {
	KeyPath           string
	CertPath          string
	IntermediatePaths []string
	FulcioURL         string
	OIDCIssuer        string
	OIDCClientID      string
}

func (ko *KeyOptions) AddFlags(cmd *cobra.Command) {
	cmd.Flags().StringVarP(&ko.KeyPath, "key", "k", "", "Path to the signing key")
	cmd.Flags().StringVar(&ko.CertPath, "certificate", "", "Path to the signing key's certificate")
	cmd.Flags().StringSliceVarP(&ko.IntermediatePaths, "intermediates", "i", []string{}, "Intermediates that link trust back to a root of trust in the policy")
	cmd.Flags().StringVar(&ko.FulcioURL, "fulcio", "", "Fulcio address to sign with")
	cmd.Flags().StringVar(&ko.OIDCIssuer, "fulcio-oidc-issuer", "", "OIDC issuer to use for authentication")
	cmd.Flags().StringVar(&ko.OIDCClientID, "fulcio-oidc-client-id", "", "OIDC client ID to use for authentication")
}
