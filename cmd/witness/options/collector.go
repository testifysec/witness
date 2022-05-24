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

type CollectorOptions struct {
	Server     string
	CACertPath string
	ClientCert string
	ClientKey  string
}

func (co *CollectorOptions) AddFlags(cmd *cobra.Command) {
	cmd.Flags().StringVar(&co.Server, "collector-server", "127.0.0.1:8080", "Collector server protocol and address")
	cmd.Flags().StringVar(&co.CACertPath, "collector-ca-path", "", "Path to the collector server's certificate CA data")
	cmd.Flags().StringVar(&co.ClientCert, "collector-client-cert-path", "", "Path to the collector client's certificate")
	cmd.Flags().StringVar(&co.ClientKey, "collector-client-key-path", "", "Path to the collector client's private key")
}
