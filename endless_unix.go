// +build !windows

package endless

import (
	"syscall"
)

// kill sends SIGTERM to the process identified by pid.
// No error is returned if the process doesn't exist.
func kill(pid int) error {
	err := syscall.Kill(pid, syscall.SIGTERM)
	if err == syscall.ESRCH {
		return nil
	}

	return err
}
