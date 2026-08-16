//go:build !linux

package fivegpn

import "context"

type processCertificateHelperRunner struct{}

func (processCertificateHelperRunner) Run(context.Context, certificateHelperSpec) error {
	return errCertificateHelperUnsupported
}
