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
	"io"
	"net/http"
)

// f is an interface that implements both the io.Writer and http.Flusher interfaces.
type f interface {
	io.Writer
	http.Flusher
}

// Flusher is a wrapper around an io.Writer that also implements the http.Flusher interface (encapsulated by the f interface)
// and its Write method calls the underlying Flush method after every write.
type Flusher struct {
	w f
}

// NewFlusher returns a new flusher that wraps the given http.ResponseWriter.
func NewFlusher(w http.ResponseWriter) (*Flusher, bool) {
	f, ok := w.(f)
	if !ok {
		return nil, false
	}
	return &Flusher{
		w: f,
	}, true
}

// Write calls the underlying Flush method after every write.
func (f *Flusher) Write(p []byte) (n int, err error) {
	n, err = f.w.Write(p)
	f.w.Flush()
	return
}
