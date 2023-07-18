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

package fastclient

import (
	"bufio"
	"io"
	"net"
	"sync"
	"sync/atomic"
	"time"

	"github.com/loopholelabs/upstream/pkg/fastclient/helpers"
	"github.com/valyala/fasthttp"
)

var clientConnPool sync.Pool

type Client struct {
	Dial                      func() (net.Conn, error)
	MaxConns                  int
	MaxIdleConnDuration       time.Duration
	MaxIdempotentCallAttempts int
	ReadBufferSize            int
	WriteBufferSize           int
	ReadTimeout               time.Duration
	WriteTimeout              time.Duration
	MaxConnWaitTimeout        time.Duration

	connsLock  sync.Mutex
	connsCount int
	conns      []*clientConn
	connsWait  *wantConnQueue

	readerPool sync.Pool
	writerPool sync.Pool

	pendingRequests int32

	connsCleanerRun bool
}

// RoundTrip does an HTTP/1.1 RoundTrip as quickly as possible and handles streaming the data with as few
// copies as possible.
//
// It's important to note that the returned *bytebufferpool.ByteBuffer will always be nil if an error is returned. This means
// if the returning function returns an error, we do not need to recycle the bytebuffer pool.
//
// It should also be noted that the *bytebufferpool.ByteBuffer will be filled in asynchronously when the response is written
// to an io.Writer (like a net.Conn) or when res.Body() is called.
func (t *Client) RoundTrip(req *fasthttp.Request, res *fasthttp.Response) error {
	var err error
	var retry bool
	maxAttempts := t.MaxIdempotentCallAttempts
	if maxAttempts <= 0 {
		maxAttempts = fasthttp.DefaultMaxIdemponentCallAttempts
	}
	isRequestRetryable := req.Header.IsGet() || req.Header.IsHead() || req.Header.IsPut()
	attempts := 0
	hasBodyStream := req.IsBodyStream()
	atomic.AddInt32(&t.pendingRequests, 1)

	for {
		retry, err = t.do(req, res)
		if err == nil || !retry {
			break
		}
		if hasBodyStream {
			break
		}
		if isRequestRetryable {
			if err != io.EOF {
				break
			}
		}
		attempts++
		if attempts >= maxAttempts {
			break
		}
	}
	atomic.AddInt32(&t.pendingRequests, -1)

	if err == io.EOF {
		err = fasthttp.ErrConnectionClosed
	}
	return err
}

func (t *Client) do(req *fasthttp.Request, res *fasthttp.Response) (bool, error) {
	customSkipBody := res.SkipBody
	res.Reset()
	res.SkipBody = customSkipBody

	reqClose := req.ConnectionClose()
	helpers.DeleteFastHTTPRequestHopHeaders(req)

	var deadline time.Time
	cc, err := t.acquireConn(reqClose)
	if err != nil {
		return false, err
	}
	conn := cc.c

	writeDeadline := deadline
	if t.WriteTimeout > 0 {
		tmpWriteDeadline := time.Now().Add(t.WriteTimeout)
		if writeDeadline.IsZero() || tmpWriteDeadline.Before(writeDeadline) {
			writeDeadline = tmpWriteDeadline
		}
	}
	if !writeDeadline.IsZero() {
		if err = conn.SetWriteDeadline(writeDeadline); err != nil {
			t.closeConn(cc)
			return true, err
		}
	}

	bw := t.acquireWriter(conn)
	err = req.Write(bw)

	if err == nil {
		err = bw.Flush()
	}
	t.releaseWriter(bw)

	if x, ok := err.(interface{ Timeout() bool }); ok && x.Timeout() {
		err = fasthttp.ErrTimeout
	}

	isConnRST := isConnectionReset(err)
	if err != nil && !isConnRST {
		t.closeConn(cc)
		return true, err
	}

	readDeadline := deadline
	if t.ReadTimeout > 0 {
		tmpReadDeadline := time.Now().Add(t.ReadTimeout)
		if readDeadline.IsZero() || tmpReadDeadline.Before(readDeadline) {
			readDeadline = tmpReadDeadline
		}
	}
	if !readDeadline.IsZero() {
		if err = conn.SetReadDeadline(readDeadline); err != nil {
			t.closeConn(cc)
			return true, err
		}
	}

	if customSkipBody || req.Header.IsHead() {
		res.SkipBody = true
	}

	br := t.acquireReader(conn)

	res.ResetBody()
	err = res.Header.Read(br)
	if err != nil {
		t.releaseReader(br)
		t.closeConn(cc)
		return err != fasthttp.ErrBodyTooLarge, err
	}

	if res.Header.StatusCode() == fasthttp.StatusContinue {
		if err = res.Header.Read(br); err != nil {
			t.releaseReader(br)
			t.closeConn(cc)
			return err != fasthttp.ErrBodyTooLarge, err
		}
	}

	resClose := res.ConnectionClose()
	helpers.DeleteFastHTTPResponseHopHeaders(res)

	if !res.SkipBody && !mustSkipContentLength(&res.Header) && res.Header.ContentLength() != 0 {
		var streamMu sync.Mutex
		contentLength := res.Header.ContentLength()
		// It's important to note that these functions only work for HTTP/1 where a request
		// and a response happen sequentially - and a single connection will only be used
		// for a single request at a time.
		//
		// This caveat is important because we're releasing our buffered reader when it is done reading a response from the
		// acquired net.Conn - and in theory the buffered reader will read as much data as is available in the net.Conn
		// every time the Read function is called. So, if the net.Conn were to contain two responses, the buffered reader
		// would read them both - and then when we released the buffered reader, we would effectively lose the second response
		// that was stored in it.
		//
		// We get away with this simply because the net.Conn will never contain two responses side by side - in HTTP/1 we will
		// send a request, read the response, and then have to send another request before another response arrives. When
		// the end of the response is read (because there's nothing left to read on the net.Conn) the buffered reader returns an io.EOF
		// error - this does not mean the connection is dead, only that the response is done. We can then safely release the buffered reader.
		streamMu.Lock()
		res.SetBodyStreamWriter(func(w *bufio.Writer) {
			var err error
			if contentLength > 0 {
				_, err = io.CopyN(w, br, int64(contentLength))
				t.releaseReader(br)
				if err != nil || reqClose || resClose || isConnRST {
					t.closeConn(cc)
				} else {
					t.releaseConn(cc)
				}
			} else if contentLength == -1 {
				err = copyBodyChunked(w, br)
				if err != nil {
					t.releaseReader(br)
					t.closeConn(cc)
				} else {
					streamMu.Lock()
					err = res.Header.ReadTrailer(br)
					t.releaseReader(br)
					streamMu.Unlock()
					if (err != nil && err != io.EOF) || (reqClose || resClose || isConnRST) {
						t.closeConn(cc)
					} else {
						t.releaseConn(cc)
					}
				}
			} else {
				var size int64
				size, err = io.Copy(w, br)
				t.releaseReader(br)
				if err != nil {
					t.closeConn(cc)
				} else {
					streamMu.Lock()
					res.Header.SetContentLength(int(size))
					streamMu.Unlock()
					if reqClose || resClose || isConnRST {
						t.closeConn(cc)
					} else {
						t.releaseConn(cc)
					}
				}
			}
		})
		streamMu.Unlock()
		return false, nil
	} else {
		t.releaseReader(br)
		t.closeConn(cc)
	}

	return false, nil
}

func (t *Client) acquireWriter(writer io.Writer) *bufio.Writer {
	v := t.writerPool.Get()
	if v == nil {
		n := t.WriteBufferSize
		if n <= 0 {
			n = 4096 * 1024
		}
		return bufio.NewWriterSize(writer, n)
	}
	bw := v.(*bufio.Writer)
	bw.Reset(writer)
	return bw
}

func (t *Client) releaseWriter(bw *bufio.Writer) {
	t.writerPool.Put(bw)
}

func (t *Client) acquireReader(reader io.Reader) *bufio.Reader {
	v := t.readerPool.Get()
	if v == nil {
		n := t.ReadBufferSize
		if n <= 0 {
			n = 4096 * 1024
		}
		return bufio.NewReaderSize(reader, n)
	}

	br := v.(*bufio.Reader)
	br.Reset(reader)
	return br
}

func (t *Client) releaseReader(br *bufio.Reader) {
	t.readerPool.Put(br)
}

func (t *Client) acquireConn(connectionClose bool) (cc *clientConn, err error) {
	createConn := false
	startCleaner := false

	var n int
	t.connsLock.Lock()
	n = len(t.conns)
	if n == 0 {
		maxConns := t.MaxConns
		if maxConns <= 0 {
			maxConns = fasthttp.DefaultMaxConnsPerHost
		}
		if t.connsCount < maxConns {
			t.connsCount++
			createConn = true
			if !t.connsCleanerRun && !connectionClose {
				startCleaner = true
				t.connsCleanerRun = true
			}
		}
	} else {
		cc = t.conns[0]
		copy(t.conns, t.conns[1:])
		t.conns[n-1] = nil
		t.conns = t.conns[:n-1]
	}
	t.connsLock.Unlock()

	if cc != nil {
		return cc, nil
	}
	if !createConn {
		if t.MaxConnWaitTimeout <= 0 {
			return nil, fasthttp.ErrNoFreeConns
		}
		timeout := t.MaxConnWaitTimeout
		tc := fasthttp.AcquireTimer(timeout)
		defer fasthttp.ReleaseTimer(tc)

		w := &wantConn{
			ready: make(chan struct{}, 1),
		}
		defer func() {
			if err != nil {
				w.cancel(t, err)
			}
		}()

		t.queueForIdle(w)

		select {
		case <-w.ready:
			return w.conn, w.err
		case <-tc.C:
			return nil, fasthttp.ErrNoFreeConns
		}
	}

	if startCleaner {
		go t.connsCleaner()
	}

	conn, err := t.Dial()
	if err != nil {
		t.decConnsCount()
		return nil, err
	}
	cc = acquireClientConn(conn)

	return cc, nil
}

func (t *Client) releaseConn(cc *clientConn) {
	cc.lastUseTime = time.Now()
	if t.MaxConnWaitTimeout <= 0 {
		t.connsLock.Lock()
		t.conns = append(t.conns, cc)
		t.connsLock.Unlock()
		return
	}

	t.connsLock.Lock()
	defer t.connsLock.Unlock()
	delivered := false
	if q := t.connsWait; q != nil && q.len() > 0 {
		for q.len() > 0 {
			w := q.popFront()
			if w.waiting() {
				delivered = w.tryDeliver(cc, nil)
				break
			}
		}
	}
	if !delivered {
		t.conns = append(t.conns, cc)
	}
}

func (t *Client) queueForIdle(w *wantConn) {
	t.connsLock.Lock()
	defer t.connsLock.Unlock()
	if t.connsWait == nil {
		t.connsWait = &wantConnQueue{}
	}
	t.connsWait.clearFront()
	t.connsWait.pushBack(w)
}

func (t *Client) connsCleaner() {
	var (
		scratch             []*clientConn
		maxIdleConnDuration = t.MaxIdleConnDuration
	)
	if maxIdleConnDuration <= 0 {
		maxIdleConnDuration = fasthttp.DefaultMaxIdleConnDuration
	}
	for {
		currentTime := time.Now()
		t.connsLock.Lock()
		conns := t.conns
		n := len(conns)
		i := 0
		for i < n && currentTime.Sub(conns[i].lastUseTime) > maxIdleConnDuration {
			i++
		}
		sleepFor := maxIdleConnDuration
		if i < n {
			sleepFor = maxIdleConnDuration - currentTime.Sub(conns[i].lastUseTime) + 1
		}
		scratch = append(scratch[:0], conns[:i]...)
		if i > 0 {
			m := copy(conns, conns[i:])
			for i = m; i < n; i++ {
				conns[i] = nil
			}
			t.conns = conns[:m]
		}
		t.connsLock.Unlock()

		// Close idle connections.
		for i, cc := range scratch {
			t.closeConn(cc)
			scratch[i] = nil
		}

		// Determine whether to stop the connsCleaner.
		t.connsLock.Lock()
		mustStop := t.connsCount == 0
		if mustStop {
			t.connsCleanerRun = false
		}
		t.connsLock.Unlock()
		if mustStop {
			break
		}

		time.Sleep(sleepFor)
	}
}

func (t *Client) closeConn(cc *clientConn) {
	t.decConnsCount()
	_ = cc.c.Close()
	releaseClientConn(cc)
}

func (t *Client) decConnsCount() {
	if t.MaxConnWaitTimeout <= 0 {
		t.connsLock.Lock()
		t.connsCount--
		t.connsLock.Unlock()
		return
	}

	t.connsLock.Lock()
	defer t.connsLock.Unlock()
	dialed := false
	if q := t.connsWait; q != nil && q.len() > 0 {
		for q.len() > 0 {
			w := q.popFront()
			if w.waiting() {
				go t.dialConnFor(w)
				dialed = true
				break
			}
		}
	}
	if !dialed {
		t.connsCount--
	}
}

func (t *Client) dialConnFor(w *wantConn) {
	conn, err := t.Dial()
	if err != nil {
		w.tryDeliver(nil, err)
		t.decConnsCount()
		return
	}

	cc := acquireClientConn(conn)
	delivered := w.tryDeliver(cc, nil)
	if !delivered {
		t.releaseConn(cc)
	}
}

type wantConnQueue struct {
	head    []*wantConn
	headPos int
	tail    []*wantConn
}

func (q *wantConnQueue) len() int {
	return len(q.head) - q.headPos + len(q.tail)
}

func (q *wantConnQueue) pushBack(w *wantConn) {
	q.tail = append(q.tail, w)
}

func (q *wantConnQueue) popFront() *wantConn {
	if q.headPos >= len(q.head) {
		if len(q.tail) == 0 {
			return nil
		}
		q.head, q.headPos, q.tail = q.tail, 0, q.head[:0]
	}

	w := q.head[q.headPos]
	q.head[q.headPos] = nil
	q.headPos++
	return w
}

func (q *wantConnQueue) peekFront() *wantConn {
	if q.headPos < len(q.head) {
		return q.head[q.headPos]
	}
	if len(q.tail) > 0 {
		return q.tail[0]
	}
	return nil
}

func (q *wantConnQueue) clearFront() (cleaned bool) {
	for {
		w := q.peekFront()
		if w == nil || w.waiting() {
			return cleaned
		}
		q.popFront()
		cleaned = true
	}
}

type wantConn struct {
	ready chan struct{}
	mu    sync.Mutex
	conn  *clientConn
	err   error
}

func (w *wantConn) cancel(t *Client, err error) {
	w.mu.Lock()
	if w.conn == nil && w.err == nil {
		close(w.ready)
	}

	conn := w.conn
	w.conn = nil
	w.err = err
	w.mu.Unlock()

	if conn != nil {
		t.releaseConn(conn)
	}
}

func (w *wantConn) waiting() bool {
	select {
	case <-w.ready:
		return false
	default:
		return true
	}
}

func (w *wantConn) tryDeliver(conn *clientConn, err error) bool {
	w.mu.Lock()
	defer w.mu.Unlock()

	if w.conn != nil || w.err != nil {
		return false
	}
	w.conn = conn
	w.err = err
	if w.conn == nil && w.err == nil {
		panic("fasthttp transport: internal error: misuse of tryDeliver")
	}
	close(w.ready)
	return true
}

type clientConn struct {
	c           net.Conn
	createdTime time.Time
	lastUseTime time.Time
}

func acquireClientConn(conn net.Conn) *clientConn {
	v := clientConnPool.Get()
	if v == nil {
		v = &clientConn{}
	}
	cc := v.(*clientConn)
	cc.c = conn
	cc.createdTime = time.Now()
	return cc
}

func releaseClientConn(cc *clientConn) {
	*cc = clientConn{}
	clientConnPool.Put(cc)
}

func mustSkipContentLength(h *fasthttp.ResponseHeader) bool {
	statusCode := h.StatusCode()
	if statusCode < 100 || statusCode == fasthttp.StatusOK {
		return false
	}
	return statusCode == fasthttp.StatusNotModified || statusCode == fasthttp.StatusNoContent || statusCode < 200
}
