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

package helpers

import (
	"bufio"
	"bytes"
	"errors"
	"github.com/gobwas/pool/pbytes"
	"github.com/rs/zerolog"
	"github.com/valyala/fasthttp"
	"golang.org/x/net/http/httpguts"
	"io"
	"net"
	"net/http"
	"strings"
	"sync"
	"unsafe"
)

var HopHeaders = []string{
	"Connection",
	"Upgrade",
	"Proxy-Connection",
	"Keep-Alive",
	"Proxy-Authenticate",
	"Proxy-Authorization",
	"Te",
	"Trailer",
	"Transfer-Encoding",
	"Server",
}

var (
	EventStreamBytes = []byte("text/event-stream")
)

// DeleteHopHeaders deletes the given headers from the given request.
func DeleteHopHeaders(h http.Header) {
	for _, val := range HopHeaders {
		h.Del(val)
	}
}

// UpgradeType returns the upgrade type (if any) for the given headers.
func UpgradeType(h http.Header) string {
	if !httpguts.HeaderValuesContainsToken(h["Connection"], "Upgrade") {
		return ""
	}
	return h.Get("Upgrade")
}

type headerValueScanner struct {
	b     []byte
	value []byte
}

func (s *headerValueScanner) next() bool {
	b := s.b
	if len(b) == 0 {
		return false
	}
	n := bytes.IndexByte(b, ';')
	if n < 0 {
		s.value = stripSpace(b)
		s.b = b[len(b):]
		return true
	}
	s.value = stripSpace(b[:n])
	s.b = b[n+1:]
	return true
}

func stripSpace(b []byte) []byte {
	for len(b) > 0 && b[0] == ' ' {
		b = b[1:]
	}
	for len(b) > 0 && b[len(b)-1] == ' ' {
		b = b[:len(b)-1]
	}
	return b
}

func caseInsensitiveCompare(a, b []byte) bool {
	if len(a) != len(b) {
		return false
	}
	for i := 0; i < len(a); i++ {
		if a[i]|0x20 != b[i]|0x20 {
			return false
		}
	}
	return true
}

func FastHTTPHasHeaderValue(s, value []byte) bool {
	var vs headerValueScanner
	vs.b = s
	for vs.next() {
		if caseInsensitiveCompare(vs.value, value) {
			return true
		}
	}
	return false
}

func FastHTTPRequestUpgradeType(req *fasthttp.Request) string {
	if !req.Header.ConnectionUpgrade() {
		return ""
	}

	return string(req.Header.Peek("Upgrade"))
}

func FastHTTPResponseUpgradeType(res *fasthttp.Response) string {
	if !res.Header.ConnectionUpgrade() {
		return ""
	}

	return string(res.Header.Peek("Upgrade"))
}

func DeleteFastHTTPRequestHopHeaders(req *fasthttp.Request) {
	for _, val := range HopHeaders {
		req.Header.Del(val)
	}
}

func DeleteFastHTTPResponseHopHeaders(res *fasthttp.Response) {
	for _, val := range HopHeaders {
		res.Header.Del(val)
	}
}

func FastHTTPUpgradeRespond(ctx *fasthttp.RequestCtx, reqUpType string, bufferedEgress *BufferedReadWriteCloser, buffer *bufio.Reader, uri *fasthttp.URI, addr string, logger *zerolog.Logger) {
	ctx.Response.ResetBody()
	err := ctx.Response.Header.Read(buffer)
	if err != nil {
		logger.Error().Err(err).Msgf("error reading response header for %s and origin %s", addr, uri.String())
		ctx.Request.SetConnectionClose()
		_ = bufferedEgress.Close()
		ctx.Error("error reading upstream response headers", fasthttp.StatusServiceUnavailable)
		return
	}

	if ctx.Response.Header.StatusCode() == fasthttp.StatusContinue {
		if err = ctx.Response.Header.Read(buffer); err != nil {
			logger.Error().Err(err).Msgf("error reading continued response header for %s and origin %s", addr, uri.String())
			ctx.Request.SetConnectionClose()
			_ = bufferedEgress.Close()
			ctx.Error("error reading upstream response headers", fasthttp.StatusServiceUnavailable)
			return
		}
	}

	if reqUpType != "" && ctx.Response.StatusCode() == fasthttp.StatusSwitchingProtocols {
		logger.Debug().Msgf("upgrade response for %s and origin %s received, hijacking connection", addr, uri.String())
		FastHTTPUpgradeCopier(ctx, reqUpType, bufferedEgress, buffer, uri, addr, logger)
		return
	}

	err = ctx.Response.ReadBody(buffer, 4096*1024)
	if err != nil {
		logger.Error().Err(err).Msgf("failed to read response body in handler for %s and origin %s", addr, uri.String())
		ctx.Request.SetConnectionClose()
		_ = bufferedEgress.Close()
		ctx.Error("upstream service unavailable", fasthttp.StatusBadGateway)
		return
	}

	if ctx.Response.Header.ContentLength() == -1 {
		err = ctx.Response.Header.ReadTrailer(buffer)
		if err != nil && !errors.Is(err, io.EOF) {
			logger.Error().Err(err).Msgf("failed to read response trailers in handler for %s and origin %s", addr, uri.String())
			ctx.Request.SetConnectionClose()
			_ = bufferedEgress.Close()
			ctx.Error("upstream service unavailable", fasthttp.StatusBadGateway)
			return
		}
	}

	DeleteFastHTTPResponseHopHeaders(&ctx.Response)
}

func FastHTTPUpgradeCopier(ctx *fasthttp.RequestCtx, reqUpType string, bufferedEgress *BufferedReadWriteCloser, buffer *bufio.Reader, uri *fasthttp.URI, addr string, logger *zerolog.Logger) {
	resUpType := FastHTTPResponseUpgradeType(&ctx.Response)
	DeleteFastHTTPResponseHopHeaders(&ctx.Response)
	if !strings.EqualFold(reqUpType, resUpType) {
		logger.Error().Msgf("tried to switch to protocol %s when %s was requested for %s and origin %s", resUpType, reqUpType, addr, uri.String())
		ctx.Request.SetConnectionClose()
		_ = bufferedEgress.Close()
		ctx.Error("protocol upgrade mismatch", fasthttp.StatusBadRequest)
		return
	}

	ctx.Response.Header.Set("Connection", "Upgrade")
	ctx.Response.Header.Set("Upgrade", resUpType)

	ctx.Hijack(FastHTTPHijackHandler(bufferedEgress, buffer))
}

func FastHTTPHijackHandler(bufferedEgress *BufferedReadWriteCloser, buffer *bufio.Reader) func(net.Conn) {
	return func(ingress net.Conn) {
		var wg sync.WaitGroup
		wg.Add(1)
		go func() {
			buf := pbytes.GetLen(4096 * 1024)
			_, _ = io.CopyBuffer(bufferedEgress, ingress, buf)
			pbytes.Put(buf)
			_ = bufferedEgress.Close()
			_ = ingress.Close()
			wg.Done()
		}()

		_, _ = io.Copy(ingress, buffer)
		_ = ingress.Close()
		_ = bufferedEgress.Close()
		wg.Wait()
	}
}

// Respond responds to the given request using the given response and the http.ResponseWriter.
//
// It deletes Hop Headers, and handles streaming responses.
func Respond(w http.ResponseWriter, req *http.Request, res *http.Response) {
	DeleteHopHeaders(res.Header)

	h := w.Header()
	for key, val := range res.Header {
		if len(val) > 1 {
			for _, v := range val {
				h.Add(key, v)
			}
		} else {
			h.Set(key, val[0])
		}
	}
	w.WriteHeader(res.StatusCode)

	var writer io.Writer
	if res.ContentLength == -1 {
		var ok bool
		writer, ok = NewFlusher(w)
		if !ok {
			req.Close = true
			http.Error(w, "misconfigured gateway", http.StatusBadGateway)
			_ = req.Body.Close()
			_ = res.Body.Close()
			return
		}
	} else {
		writer = w
	}
	_, err := io.Copy(writer, res.Body)
	if err != nil {
		req.Close = true
	}

	_ = req.Body.Close()
	_ = res.Body.Close()
}

func BytesToString(b []byte) string {
	return *(*string)(unsafe.Pointer(&b))
}
