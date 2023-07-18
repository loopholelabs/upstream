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
	"bytes"
	"errors"
	"fmt"
	"io"
)

var (
	strCRLF           = []byte("\r\n")
	errEmptyHexNum    = errors.New("empty hex number")
	errTooLargeHexNum = errors.New("too large hex number")
)

func copyBodyChunked(w io.Writer, r *bufio.Reader) error {
	var strCRLFBytes [2]byte
	for {
		chunkSize, err := parseChunkSize(r)
		if err != nil {
			return err
		}
		if chunkSize == 0 {
			return nil
		}
		_, err = io.CopyN(w, r, int64(chunkSize))
		if err != nil {
			return err
		}
		_, err = r.Read(strCRLFBytes[:])
		if err != nil {
			return err
		}
		if !bytes.Equal(strCRLFBytes[:], strCRLF) {
			return fmt.Errorf("cannot find crlf at the end of chunk")
		}
	}
}

func parseChunkSize(r *bufio.Reader) (int, error) {
	n, err := readHexInt(r)
	if err != nil {
		return -1, err
	}
	for {
		c, err := r.ReadByte()
		if err != nil {
			return -1, fmt.Errorf("cannot read '\r' char at the end of chunk size: %w", err)
		}
		// Skip chunk extension after chunk size.
		// Add support later if anyone needs it.
		if c != '\r' {
			continue
		}
		if err := r.UnreadByte(); err != nil {
			return -1, fmt.Errorf("cannot unread '\r' char at the end of chunk size: %w", err)
		}
		break
	}
	err = readCrLf(r)
	if err != nil {
		return -1, err
	}
	return n, nil
}

func readCrLf(r *bufio.Reader) error {
	for _, exp := range []byte{'\r', '\n'} {
		c, err := r.ReadByte()
		if err != nil {
			return fmt.Errorf("cannot read %q char at the end of chunk size: %w", exp, err)
		}
		if c != exp {
			return fmt.Errorf("unexpected char %q at the end of chunk size. Expected %q", c, exp)
		}
	}
	return nil
}

func readHexInt(r *bufio.Reader) (int, error) {
	n := 0
	i := 0
	var k int
	for {
		c, err := r.ReadByte()
		if err != nil {
			if err == io.EOF && i > 0 {
				return n, nil
			}
			return -1, err
		}
		k = int(hex2intTable[c])
		if k == 16 {
			if i == 0 {
				return -1, errEmptyHexNum
			}
			if err := r.UnreadByte(); err != nil {
				return -1, err
			}
			return n, nil
		}
		if i >= maxHexIntChars {
			return -1, errTooLargeHexNum
		}
		n = (n << 4) | k
		i++
	}
}
