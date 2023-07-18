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
	"crypto/tls"
	"github.com/quic-go/quic-go/http3"
	"golang.org/x/net/http2"
)

// CertificateEvent is the event that is emitted when a certificate is created, updated, or deleted
type CertificateEvent struct {
	// ID is the unique identifier of the certificate's domain
	ID string

	// Deleted indicates whether the certificate was deleted
	Deleted bool

	// CertURL is the URL of the certificate
	// If the certificate was deleted, this will be empty
	CertURL string

	// Domain is the domain of the certificate
	// If the certificate was deleted, this will be empty
	Domain string

	// Certificate is the certificate that was created or updated.
	// If the certificate was deleted, this will be nil
	Certificate tls.Certificate
}

// RouteEvent is the event that is emitted when a new route is created, updated, or deleted
type RouteEvent struct {
	// ID is the unique identifier of the route, which is the domain name for
	// incoming requests
	ID string

	// Deleted indicates whether the route was deleted
	Deleted bool

	// Upstream is the upstream of the route
	Upstream string
}

func (p *Upstream) subscribeToCertificateEvents(events <-chan *CertificateEvent) {
	defer p.wg.Done()
	for {
		select {
		case <-p.ctx.Done():
			p.logger.Info().Msg("certificate event subscription stopped")
			return
		case event := <-events:
			if event.Deleted {
				p.logger.Debug().Msgf("certificate %s deleted", event.ID)
				p.certificatesMu.Lock()
				delete(p.certificates, event.ID)
				p.certificatesMu.Unlock()
			} else {
				p.logger.Debug().Msgf("certificate event %s created or updated", event.ID)
				tlsConfig := &tls.Config{
					MinVersion:   tls.VersionTLS12,
					NextProtos:   []string{http3.NextProtoH3, http3.NextProtoH3Draft29, http2.NextProtoTLS, "http/1.1"},
					Certificates: []tls.Certificate{event.Certificate},
				}
				p.certificatesMu.Lock()
				p.certificates[event.Domain] = tlsConfig
				p.certificatesMu.Unlock()
			}
		}
	}
}

func (p *Upstream) subscribeToRootCertificateEvents(events <-chan *CertificateEvent) {
	defer p.wg.Done()
	for {
		select {
		case <-p.ctx.Done():
			p.logger.Info().Msg("root certificate event subscription stopped")
			return
		case event := <-events:
			if event.Deleted {
				p.logger.Debug().Msgf("root certificate %s deleted", event.ID)
				p.rootCertificatesMu.Lock()
				delete(p.rootCertificates, event.ID)
				p.rootCertificatesMu.Unlock()
			} else {
				p.logger.Debug().Msgf("root certificate event %s created or updated", event.ID)
				tlsConfig := &tls.Config{
					MinVersion:   tls.VersionTLS12,
					NextProtos:   []string{http3.NextProtoH3, http3.NextProtoH3Draft29, http2.NextProtoTLS, "http/1.1"},
					Certificates: []tls.Certificate{event.Certificate},
				}
				p.rootCertificatesMu.Lock()
				p.rootCertificates[event.Domain] = tlsConfig
				p.rootCertificatesMu.Unlock()
			}
		}
	}
}

func (p *Upstream) subscribeToRouteEvents(events <-chan *RouteEvent) {
	defer p.wg.Done()
	for {
		select {
		case <-p.ctx.Done():
			p.logger.Info().Msg("route event subscription stopped")
			return
		case event := <-events:
			if event.Deleted {
				p.logger.Debug().Msgf("route %s deleted", event.ID)
				p.routesMu.Lock()
				delete(p.routes, event.ID)
				p.routesMu.Unlock()
			} else {
				p.logger.Debug().Msgf("route event %s created or updated", event.ID)
				route := &Route{
					id:         event.ID,
					upstream:   event.Upstream,
					h3Provider: p.newH3Provider(event.Upstream),
				}
				p.routesMu.Lock()
				p.routes[event.ID] = route
				p.routesMu.Unlock()
			}
		}
	}
}
