package upstream

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"github.com/quic-go/quic-go"
	"github.com/quic-go/quic-go/http3"
	"github.com/rs/zerolog"
	"github.com/valyala/fasthttp"
	"github.com/valyala/tcplisten"
	"golang.org/x/net/http2"
	"io"
	"log"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"
)

var (
	ErrMissingSNI = errors.New("missing SNI")
	ErrUnknownSNI = errors.New("unknown SNI")
)

type Options struct {
	LogName       string
	ListenAddress string
}

type Upstream struct {
	logger  *zerolog.Logger
	options *Options
	storage Storage

	certificatesMu sync.RWMutex
	certificates   map[string]*tls.Config

	rootCertificatesMu sync.RWMutex
	rootCertificates   map[string]*tls.Config

	routesMu sync.RWMutex
	routes   map[string]*Route

	h3Listener   *quic.EarlyListener
	h12Listener  net.Listener
	altSVCHeader string

	h1Server     *fasthttp.Server
	h2Server     *http2.Server
	h2ServerOpts *http2.ServeConnOpts
	h3Server     *http3.Server

	ctx    context.Context
	cancel context.CancelFunc
	wg     sync.WaitGroup
}

func New(options *Options, storage Storage, logger *zerolog.Logger) *Upstream {
	l := logger.With().Str(options.LogName, "UPSTREAM").Logger()
	return &Upstream{
		logger:           &l,
		options:          options,
		storage:          storage,
		certificates:     make(map[string]*tls.Config),
		rootCertificates: make(map[string]*tls.Config),
		routes:           make(map[string]*Route),
	}
}

func (p *Upstream) Start() error {
	p.ctx, p.cancel = context.WithCancel(context.Background())

	p.certificatesMu.Lock()
	certificateEvents := p.storage.SubscribeToCertificates(p.ctx)
	p.wg.Add(1)
	go p.subscribeToCertificateEvents(certificateEvents)
	p.logger.Info().Msg("subscribed to certificate events")
	domains, err := p.storage.ListCertificates(p.ctx, true)
	if err != nil {
		p.certificatesMu.Unlock()
		return fmt.Errorf("failed to list certificates: %w", err)
	}
	for _, domain := range domains {
		p.certificates[domain.Domain] = &tls.Config{
			MinVersion:   tls.VersionTLS12,
			NextProtos:   []string{http3.NextProtoH3, http3.NextProtoH3Draft29, http2.NextProtoTLS, "http/1.1"},
			Certificates: []tls.Certificate{domain.Certificate},
		}
	}
	p.certificatesMu.Unlock()

	p.rootCertificatesMu.Lock()
	rootCertificateEvents := p.storage.SubscribeToRootCertificates(p.ctx)
	p.wg.Add(1)
	go p.subscribeToRootCertificateEvents(rootCertificateEvents)
	p.logger.Info().Msg("subscribed to root certificate events")
	roots, err := p.storage.ListRootCertificates(p.ctx, true)
	if err != nil {
		p.rootCertificatesMu.Unlock()
		return fmt.Errorf("failed to list root certificates: %w", err)
	}
	for _, root := range roots {
		p.rootCertificates[root.Domain] = &tls.Config{
			MinVersion:   tls.VersionTLS12,
			NextProtos:   []string{http3.NextProtoH3, http3.NextProtoH3Draft29, http2.NextProtoTLS, "http/1.1"},
			Certificates: []tls.Certificate{root.Certificate},
		}
	}
	p.rootCertificatesMu.Unlock()

	p.routesMu.Lock()
	routeEvents := p.storage.SubscribeToRoutes(p.ctx)
	p.wg.Add(1)
	go p.subscribeToRouteEvents(routeEvents)
	p.logger.Info().Msg("subscribed to route events")
	routes, err := p.storage.ListRoutes(p.ctx)
	if err != nil {
		p.routesMu.Unlock()
		return fmt.Errorf("failed to list routes: %w", err)
	}
	for _, route := range routes {
		p.routes[route.ID] = &Route{
			id:         route.ID,
			upstream:   route.Upstream,
			h3Provider: p.newH3Provider(route.Upstream),
		}
	}
	p.routesMu.Unlock()

	tlsConfig := &tls.Config{
		MinVersion:         tls.VersionTLS12,
		GetConfigForClient: p.getTLSConfig,
	}

	udpAddr, err := net.ResolveUDPAddr("udp", p.options.ListenAddress)
	if err != nil {
		return err
	}

	packetConn, err := net.ListenUDP("udp", udpAddr)
	if err != nil {
		return err
	}
	p.h3Listener, err = quic.ListenEarly(packetConn, tlsConfig, &quic.Config{
		Allow0RTT:                true,
		RequireAddressValidation: func(_ net.Addr) bool { return false },
	})
	if err != nil {
		_ = packetConn.Close()
		return err
	}
	defer func() {
		_ = p.h3Listener.Close()
	}()

	listenConfig := tcplisten.Config{
		DeferAccept: true,
		FastOpen:    true,
	}

	tcpConn, err := listenConfig.NewListener("tcp4", p.options.ListenAddress)
	if err != nil {
		return err
	}
	defer func() {
		_ = tcpConn.Close()
	}()

	p.altSVCHeader = fmt.Sprintf("h3=\":%d\"; ma=86400,h3-29=\":%d\"; ma=86400", udpAddr.Port, udpAddr.Port)
	p.h12Listener = tls.NewListener(tcpConn, tlsConfig)
	defer func() {
		_ = p.h12Listener.Close()
	}()

	p.h1Server = &fasthttp.Server{
		Handler:               p.http1Handler,
		TCPKeepalive:          true,
		NoDefaultServerHeader: true,
		NoDefaultDate:         true,
		NoDefaultContentType:  true,
		CloseOnShutdown:       true,
		StreamRequestBody:     true,
		Logger:                p.logger,
		TLSConfig:             tlsConfig,
	}

	p.h2Server = &http2.Server{
		IdleTimeout:      time.Second * 5,
		MaxReadFrameSize: 256000,
	}

	p.h2ServerOpts = &http2.ServeConnOpts{
		Handler: http.HandlerFunc(p.http2Handler),
		BaseConfig: &http.Server{
			ErrorLog: log.New(io.Discard, "", log.LstdFlags),
		},
		Context: p.ctx,
	}

	p.h3Server = &http3.Server{
		Handler: http.HandlerFunc(p.http3Handler),
	}

	hErr := make(chan error, 1)
	qErr := make(chan error, 1)
	p.wg.Add(2)
	go func() {
		hErr <- p.listenHTTP12()
		p.wg.Done()
	}()
	go func() {
		qErr <- p.h3Server.ServeListener(p.h3Listener)
		p.wg.Done()
	}()

	select {
	case err := <-hErr:
		_ = p.h3Server.Close()
		if !errors.Is(err, http.ErrServerClosed) {
			return err
		}
		return nil
	case err := <-qErr:
		_ = p.h1Server.Shutdown()
		if !errors.Is(err, quic.ErrServerClosed) {
			return err
		}
		return nil
	}
}

func (p *Upstream) Stop() error {
	if p.cancel != nil {
		p.cancel()
	}

	if p.h3Server != nil {
		err := p.h3Server.Close()
		if err != nil {
			return err
		}
	}

	if p.h2ServerOpts != nil {
		err := p.h2ServerOpts.BaseConfig.Close()
		if err != nil {
			return err
		}
	}

	if p.h1Server != nil {
		err := p.h1Server.Shutdown()
		if err != nil {
			return err
		}
	}

	p.wg.Wait()
	return nil
}

func (p *Upstream) getTLSConfig(hello *tls.ClientHelloInfo) (*tls.Config, error) {
	if len(hello.ServerName) == 0 {
		return nil, ErrMissingSNI
	}

	p.certificatesMu.RLock()
	tlsConfig, ok := p.certificates[hello.ServerName]
	p.certificatesMu.RUnlock()
	if ok {
		return tlsConfig, nil
	}

	prefixIndex := strings.Index(hello.ServerName, ".")
	if prefixIndex == -1 {
		return nil, fmt.Errorf("unknown SNI: %s: %w", hello.ServerName, ErrUnknownSNI)
	}

	p.rootCertificatesMu.RLock()
	tlsConfig, ok = p.rootCertificates[hello.ServerName[prefixIndex+1:]]
	p.rootCertificatesMu.RUnlock()

	if ok {
		return tlsConfig, nil
	}

	return nil, fmt.Errorf("unknown SNI: %s: %w", hello.ServerName, ErrUnknownSNI)
}
