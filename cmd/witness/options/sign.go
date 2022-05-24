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

type SignOptions struct {
	SpiffeOptions SpiffeOptions
	KeyOptions    KeyOptions
	DataType      string
	OutFilePath   string
	InFilePath    string
}

func (so *SignOptions) AddFlags(cmd *cobra.Command) {
	so.KeyOptions.AddFlags(cmd)
	so.SpiffeOptions.AddFlags(cmd)
	_ = cmd.Flags().MarkHidden("spiffe-server-id")
	cmd.Flags().StringVarP(&so.DataType, "datatype", "t", "https://witness.testifysec.com/policy/v0.1", "The URI reference to the type of data being signed. Defaults to the Witness policy type")
	cmd.Flags().StringVarP(&so.OutFilePath, "outfile", "o", "", "File to write signed data. Defaults to stdout")
	cmd.Flags().StringVarP(&so.InFilePath, "infile", "f", "", "Witness policy file to sign")
}
