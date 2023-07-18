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

package temporary

import "time"

const (
	// MaxBackoff is the maximum amount ot time to wait before retrying to accept from a listener
	MaxBackoff = time.Second

	// MinBackoff is the minimum amount ot time to wait before retrying to accept from a listener
	MinBackoff = time.Millisecond * 5

	// Timeout is the amount of time to wait before timing out a connection
	Timeout = time.Second * 5
)

// Temporary is an interface used to check if an error is recoverable
type Temporary interface {
	Temporary() bool
}
