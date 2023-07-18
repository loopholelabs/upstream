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
	"bytes"
	"crypto/tls"
	"errors"
	"github.com/loopholelabs/upstream/internal/temporary"
	"github.com/loopholelabs/upstream/pkg/fastclient/helpers"
	"github.com/valyala/fasthttp"
	"io"
	"net"
	"net/http"
	"net/url"
	"time"
)

var (
	emptyTime = time.Time{}
)

func (p *Upstream) listenHTTP12() error {
	var backoff time.Duration
	for {
		conn, err := p.h12Listener.Accept()
		if err != nil {
			if ne, ok := err.(temporary.Temporary); ok && ne.Temporary() {
				if backoff == 0 {
					backoff = temporary.MinBackoff
				} else {
					backoff *= 2
				}
				if backoff > temporary.MaxBackoff {
					backoff = temporary.MinBackoff
				}
				p.logger.Warn().Err(err).Msgf("temporary accept error in discovery, retrying in %d", backoff)
				time.Sleep(backoff)
				continue
			}
			if errors.Is(err, net.ErrClosed) {
				return nil
			}
			return err
		}
		backoff = 0

		p.wg.Add(1)
		go p.handleConn(conn.(*tls.Conn))
	}
}

func (p *Upstream) handleConn(conn *tls.Conn) {
	defer p.wg.Done()

	err := conn.SetDeadline(time.Now().Add(5 * time.Second))
	if err != nil {
		p.logger.Error().Err(err).Msgf("setting read deadline failed with connection %s", conn.RemoteAddr())
		_ = conn.Close()
		return
	}

	err = conn.Handshake()
	if err != nil {
		p.logger.Error().Err(err).Msgf("handshake failed with connection %s", conn.RemoteAddr())
		_ = conn.Close()
		return
	}

	_ = conn.SetDeadline(emptyTime)
	connState := conn.ConnectionState()
	switch connState.NegotiatedProtocol {
	case "h2":
		p.h2Server.ServeConn(conn, p.h2ServerOpts)
		_ = conn.Close()
	case "http/1.1":
		fallthrough
	default:
		_ = p.h1Server.ServeConn(conn)
	}
}

func (p *Upstream) http3Handler(wr http.ResponseWriter, req *http.Request) {
	hostname := req.Host
	if req.URL.Host != "" && req.URL.Host != hostname {
		p.logger.Error().Msgf("host mismatch: %s != %s", req.URL.Host, req.Host)
		http.Error(wr, "URL host mismatch", http.StatusBadGateway)
		return
	}

	reqUpType := helpers.UpgradeType(req.Header)
	if reqUpType != "" {
		p.logger.Error().Msgf("unsupported upgrade type %s", reqUpType)
		http.Error(wr, "unsupported upgrade type", http.StatusBadGateway)
		return
	}

	helpers.DeleteHopHeaders(req.Header)

	if remoteIP := req.Header.Get("X-Forwarded-For"); remoteIP == "" {
		req.Header.Set("X-Forwarded-For", req.RemoteAddr)
	} else {
		req.Header.Set("X-Forwarded-For", remoteIP+", "+req.RemoteAddr)
	}
	req.Header.Set("X-Forwarded-Version", "HTTP/3")

	wr.Header().Set("Alt-Svc", p.altSVCHeader)

	p.routesMu.RLock()
	route, ok := p.routes[hostname]
	p.routesMu.RUnlock()
	if !ok {
		p.logger.Error().Msgf("unknown route %s", hostname)
		http.Error(wr, "unknown route", http.StatusBadGateway)
		return
	}

	req.Host = route.upstream
	req.URL.Host = route.upstream
	req.URL.Scheme = "https"

	duration := time.Now()
RETRY:
	res, err := route.h3Provider.RoundTrip(req)
	if err != nil {
		if err.Error() == "Application error 0x100 (remote)" {
			goto RETRY
		}
		p.logger.Error().Err(err).Msgf("failed to roundtrip http/3 for %s and origin %s", hostname, req.URL.String())
		http.Error(wr, "upstream service unavailable", http.StatusBadGateway)
		return
	}

	wr.Header().Set("X-Proxy-Duration", time.Since(duration).String())

	helpers.Respond(wr, req, res)
}

func (p *Upstream) http2Handler(wr http.ResponseWriter, req *http.Request) {
	hostname := req.Host
	if req.URL.Host != "" && req.URL.Host != hostname {
		p.logger.Error().Msgf("host mismatch: %s != %s", req.URL.Host, req.Host)
		http.Error(wr, "URL host mismatch", http.StatusBadGateway)
		return
	}

	reqUpType := helpers.UpgradeType(req.Header)
	if reqUpType != "" {
		p.logger.Error().Msgf("unsupported upgrade type %s", reqUpType)
		http.Error(wr, "unsupported upgrade type", http.StatusBadGateway)
		return
	}

	helpers.DeleteHopHeaders(req.Header)

	if remoteIP := req.Header.Get("X-Forwarded-For"); remoteIP == "" {
		req.Header.Set("X-Forwarded-For", req.RemoteAddr)
	} else {
		req.Header.Set("X-Forwarded-For", remoteIP+", "+req.RemoteAddr)
	}
	req.Header.Set("X-Forwarded-Version", "HTTP/2")

	wr.Header().Set("Alt-Svc", p.altSVCHeader)

	p.routesMu.RLock()
	route, ok := p.routes[hostname]
	p.routesMu.RUnlock()
	if !ok {
		p.logger.Error().Msgf("unknown route %s", hostname)
		http.Error(wr, "unknown route", http.StatusBadGateway)
		return
	}

	req.Host = route.upstream
	req.URL.Host = route.upstream
	req.URL.Scheme = "https"
	req.Proto = "HTTP/3"
	req.ProtoMajor = 3
	req.ProtoMinor = 0

	duration := time.Now()
RETRY:
	res, err := route.h3Provider.RoundTrip(req)
	if err != nil {
		if err.Error() == "Application error 0x100 (remote)" {
			goto RETRY
		}
		p.logger.Error().Err(err).Msgf("failed to roundtrip http/2 for %s and origin %s", hostname, req.URL.String())
		http.Error(wr, "upstream service unavailable", http.StatusBadGateway)
		return
	}

	wr.Header().Set("X-Proxy-Duration", time.Since(duration).String())

	helpers.Respond(wr, req, res)
}

func (p *Upstream) http1Handler(ctx *fasthttp.RequestCtx) {
	uri := ctx.Request.URI()
	hostname := string(uri.Host())
	headerHost := helpers.BytesToString(ctx.Request.Header.Host())
	if hostname != headerHost {
		p.logger.Error().Msgf("host mismatch: %s != %s", hostname, headerHost)
		ctx.Request.SetConnectionClose()
		ctx.Error("URL host mismatch", fasthttp.StatusBadGateway)
		return
	}

	reqUpType := helpers.FastHTTPRequestUpgradeType(&ctx.Request)
	if reqUpType != "" {
		p.logger.Error().Msgf("unsupported upgrade type: %s", reqUpType)
		ctx.Request.SetConnectionClose()
		ctx.Error("unsupported upgrade type", fasthttp.StatusBadGateway)
		return
	}

	helpers.DeleteFastHTTPRequestHopHeaders(&ctx.Request)

	if remoteIP := ctx.Request.Header.Peek("X-Forwarded-For"); remoteIP == nil {
		ctx.Request.Header.Set("X-Forwarded-For", ctx.RemoteIP().String())
	} else {
		ctx.Request.Header.Set("X-Forwarded-For", string(remoteIP)+", "+ctx.RemoteIP().String())
	}

	ctx.Request.Header.Set("X-Forwarded-Version", "HTTP/1.1")

	var req http.Request
	req.Body = io.NopCloser(bytes.NewReader(ctx.Request.Body()))
	req.URL = new(url.URL)
	req.URL.Path = helpers.BytesToString(ctx.Request.URI().Path())
	req.URL.RawQuery = helpers.BytesToString(ctx.Request.URI().QueryString())
	req.Method = helpers.BytesToString(ctx.Request.Header.Method())

	req.ContentLength = int64(ctx.Request.Header.ContentLength())
	req.RemoteAddr = ctx.RemoteAddr().String()
	req.TLS = ctx.TLSConnectionState()
	req.RequestURI = helpers.BytesToString(ctx.RequestURI())
	req.Header = make(http.Header)

	ctx.Request.Header.VisitAll(func(k, v []byte) {
		sk := helpers.BytesToString(k)
		sv := helpers.BytesToString(v)
		switch sk {
		case "Transfer-Encoding":
			req.TransferEncoding = append(req.TransferEncoding, sv)
		default:
			req.Header.Set(sk, sv)
		}
	})

	p.routesMu.RLock()
	route, ok := p.routes[hostname]
	p.routesMu.RUnlock()
	if !ok {
		p.logger.Error().Msgf("unknown route %s", hostname)
		ctx.Request.SetConnectionClose()
		ctx.Error("unknown route", fasthttp.StatusBadGateway)
		return
	}

	req.Host = route.upstream
	req.URL.Host = route.upstream
	req.URL.Scheme = "https"
	req.Proto = "HTTP/3"
	req.ProtoMajor = 3
	req.ProtoMinor = 0

	duration := time.Now()
RETRY:
	res, err := route.h3Provider.RoundTrip(req.WithContext(ctx))
	if err != nil {
		if err.Error() == "Application error 0x100 (remote)" {
			goto RETRY
		}
		p.logger.Error().Err(err).Msgf("failed to roundtrip http/1.1 for %s and origin %s", hostname, uri.String())
		ctx.Request.SetConnectionClose()
		ctx.Error("upstream service unavailable", fasthttp.StatusBadGateway)
		return
	}

	ctx.Response.SetStatusCode(res.StatusCode)
	ctx.Response.SetBodyStream(res.Body, int(res.ContentLength))

	haveContentType := false
	for k, vv := range res.Header {
		if k == fasthttp.HeaderContentType {
			haveContentType = true
		}
		for _, v := range vv {
			ctx.Response.Header.Add(k, v)
		}
	}

	if !haveContentType {
		l := 512
		b := ctx.Response.Body()
		if len(b) < 512 {
			l = len(b)
		}
		ctx.Response.Header.Set(fasthttp.HeaderContentType, http.DetectContentType(b[:l]))
	}

	ctx.Response.Header.Set("X-Proxy-Duration", time.Since(duration).String())
	ctx.Response.Header.Set("Alt-Svc", p.altSVCHeader)
}
