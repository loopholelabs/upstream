/*
	Copyright 2023 Loophole Labs

	Licensed under the Apache License, Version 2.0 (the "License");
	you may not use this file except in compliance with the License.
	You may obtain a copy of the License at

		   http://www.apache.org/licenses/LICENSE-2.0

	Unless required by applicable law or agreed to in writing, software
	distributed under the License is distributed on an "AS IS" BASIS,
	WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
	See the License for the specific language governing permissions and
	limitations under the License.
*/

package config

import (
	"errors"
	"github.com/loopholelabs/upstream"
	"github.com/spf13/cobra"
	"github.com/spf13/pflag"
)

var (
	ErrListenAddressRequired = errors.New("listen address is required")
)

const (
	DefaultDisabled = false
)

type Config struct {
	Disabled      bool   `mapstructure:"disabled"`
	ListenAddress string `mapstructure:"listen_address"`
}

func New() *Config {
	return &Config{
		Disabled: DefaultDisabled,
	}
}

func (c *Config) Validate() error {
	if !c.Disabled {
		if c.ListenAddress == "" {
			return ErrListenAddressRequired
		}
	}

	return nil
}

func (c *Config) RootPersistentFlags(flags *pflag.FlagSet) {
	flags.BoolVar(&c.Disabled, "upstream-disabled", false, "Disable the upstream service")
	flags.StringVar(&c.ListenAddress, "upstream-listen-address", "", "The listen address for the upstream service")
}

func (c *Config) GlobalRequiredFlags(cmd *cobra.Command) error {
	err := cmd.MarkFlagRequired("upstream-listen-address")
	if err != nil {
		return err
	}

	return nil
}

func (c *Config) GenerateOptions(logName string) *upstream.Options {
	return &upstream.Options{
		LogName:       logName,
		ListenAddress: c.ListenAddress,
	}
}
