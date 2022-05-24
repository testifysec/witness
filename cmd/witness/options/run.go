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

type RunOptions struct {
	KeyOptions       KeyOptions
	WorkingDir       string
	Attestations     []string
	OutFilePath      string
	StepName         string
	RekorServer      string
	Tracing          bool
	CollectorOptions CollectorOptions
	SpiffeOptions    SpiffeOptions
}

func (ro *RunOptions) AddFlags(cmd *cobra.Command) {
	ro.KeyOptions.AddFlags(cmd)
	ro.CollectorOptions.AddFlags(cmd)
	ro.SpiffeOptions.AddFlags(cmd)
	cmd.Flags().StringVarP(&ro.WorkingDir, "workingdir", "d", "", "Directory from which commands will run")
	cmd.Flags().StringSliceVarP(&ro.Attestations, "attestations", "a", []string{"environment", "git"}, "Attestations to record")
	cmd.Flags().StringVarP(&ro.OutFilePath, "outfile", "o", "", "File to which to write signed data.  Defaults to stdout")
	cmd.Flags().StringVarP(&ro.StepName, "step", "s", "", "Name of the step being run")
	cmd.Flags().StringVarP(&ro.RekorServer, "rekor-server", "r", "", "Rekor server to store attestations")
	cmd.Flags().BoolVar(&ro.Tracing, "trace", false, "Enable tracing for the command")
}
