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
	"github.com/gobwas/pool/pbufio"
	"io"
)

var _ io.ReadWriteCloser = (*BufferedReadWriteCloser)(nil)

func NewBufferedReadWriteCloser(rwc io.ReadWriteCloser) *BufferedReadWriteCloser {
	return &BufferedReadWriteCloser{
		br:          pbufio.GetReader(rwc, 4096*1024),
		WriteCloser: rwc,
	}
}

type BufferedReadWriteCloser struct {
	br *bufio.Reader
	io.WriteCloser
}

func (b *BufferedReadWriteCloser) Buffer() *bufio.Reader {
	return b.br
}

func (b *BufferedReadWriteCloser) Read(p []byte) (n int, err error) {
	return b.br.Read(p)
}

func (b *BufferedReadWriteCloser) Close() error {
	if b.br != nil {
		pbufio.PutReader(b.br)
		b.br = nil
	}
	return b.WriteCloser.Close()
}
