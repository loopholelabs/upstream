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

package upstream

import (
	"context"
	"crypto/tls"
	"github.com/quic-go/quic-go"
	"github.com/quic-go/quic-go/http3"
)

type Route struct {
	id         string
	upstream   string
	h3Provider *http3.RoundTripper
}

func (p *Upstream) newH3Provider(sni string) *http3.RoundTripper {
	tlsConfig := &tls.Config{
		MinVersion: tls.VersionTLS13,
		ServerName: sni,
	}
	return &http3.RoundTripper{
		TLSClientConfig: tlsConfig,
		EnableDatagrams: true,
		Dial: func(ctx context.Context, addr string, tlsConfig *tls.Config, cfg *quic.Config) (quic.EarlyConnection, error) {
			return quic.DialAddrEarly(ctx, addr, tlsConfig, cfg)
		},
	}
}
