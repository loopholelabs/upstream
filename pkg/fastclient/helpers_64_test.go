//go:build amd64 || arm64 || ppc64 || ppc64le || s390x

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
	"github.com/stretchr/testify/assert"
	"testing"
)

func testReadHexIntError(t *testing.T, s string) {
	r := bytes.NewBufferString(s)
	br := bufio.NewReader(r)
	n, err := readHexInt(br)
	assert.Error(t, err)
	assert.Less(t, n, 0)
}

func testReadHexIntSuccess(t *testing.T, s string, expectedN int) {
	r := bytes.NewBufferString(s)
	br := bufio.NewReader(r)
	n, err := readHexInt(br)
	assert.NoError(t, err)
	assert.Equal(t, expectedN, n)
}

func TestReadHexIntError(t *testing.T) {
	t.Parallel()

	testReadHexIntError(t, "")
	testReadHexIntError(t, "ZZZ")
	testReadHexIntError(t, "-123")
	testReadHexIntError(t, "+434")
}

func TestReadHexIntSuccess(t *testing.T) {
	t.Parallel()

	testReadHexIntSuccess(t, "0", 0)
	testReadHexIntSuccess(t, "fF", 0xff)
	testReadHexIntSuccess(t, "00abc", 0xabc)
	testReadHexIntSuccess(t, "7fffffff", 0x7fffffff)
	testReadHexIntSuccess(t, "000", 0)
	testReadHexIntSuccess(t, "1234ZZZ", 0x1234)
	testReadHexIntSuccess(t, "7ffffffffffffff", 0x7ffffffffffffff)
}
