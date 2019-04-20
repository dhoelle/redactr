//+build tools

package tools

//
// This file defines dependencies for external tools.
// As of April 2019 this is the recommended approach,
// although it may change going forward.
//
// See:
//   - https://github.com/golang/go/wiki/Modules#how-can-i-track-tool-dependencies-for-a-module
//   - https://github.com/golang/go/issues/25922
//

import (
	// counterfeiter is used to generate fakes
	_ "github.com/maxbrunsfeld/counterfeiter/v6"
)
