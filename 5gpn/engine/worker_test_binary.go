package engine

import "flag"

// workerTestBinary is true only when the generated Go test main linked the
// testing flags. It does not depend on user-controlled argv or executable name.
func workerTestBinary() bool {
	return flag.Lookup("test.v") != nil && flag.Lookup("test.run") != nil
}
