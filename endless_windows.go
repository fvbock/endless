// +build windows

package endless

import (
	"os"
	"syscall"
)

// errInvalidParamter is the Windows ERROR_INVALID_PARAMETER error
var errInvalidParamter = syscall.Errno(0x57)

// kill calls TerminateProcess on the process identified by pid.
// No error is returned if the process doesn't exist.
func kill(pid int) error {
	h, err := syscall.OpenProcess(syscall.PROCESS_TERMINATE, false, uint32(pid))
	if err == errInvalidParamter {
		// Process not found
		return nil
	} else if err != nil {
		return os.NewSyscallError("OpenProcess", err)
	}
	defer syscall.CloseHandle(h)
	if err = syscall.TerminateProcess(h, 1); err != nil {
		if err == errInvalidParamter {
			// Process not found
			return nil
		}
		return os.NewSyscallError("TerminateProcess", err)
	}

	return nil
}
