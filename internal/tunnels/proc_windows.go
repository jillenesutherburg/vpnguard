//go:build windows

package tunnels

import (
	"fmt"
	"os/exec"
	"strings"
	"syscall"
	"unsafe"

	"golang.org/x/sys/windows"
)

// proc wraps a started process together with a Job Object. The job is
// configured with JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE: closing the job
// handle terminates the entire process tree, including processes whose
// parent already exited (the classic ".bat spawned ssh.exe and quit"
// orphan that taskkill /T misses).
type proc struct {
	cmd *exec.Cmd
	job windows.Handle
}

func startProcess(script string, args []string) (*proc, error) {
	var cmd *exec.Cmd
	lower := strings.ToLower(script)
	if strings.HasSuffix(lower, ".bat") || strings.HasSuffix(lower, ".cmd") {
		cmdArgs := append([]string{"/C", script}, args...)
		cmd = exec.Command("cmd.exe", cmdArgs...)
	} else {
		cmd = exec.Command(script, args...)
	}
	cmd.SysProcAttr = &syscall.SysProcAttr{
		HideWindow:    true,
		CreationFlags: windows.CREATE_NEW_PROCESS_GROUP | windows.CREATE_NO_WINDOW,
	}
	if err := cmd.Start(); err != nil {
		return nil, err
	}

	job, err := newKillOnCloseJob()
	if err != nil {
		// Degraded mode: run without a job (kill falls back to Process.Kill).
		return &proc{cmd: cmd}, nil
	}
	h, err := windows.OpenProcess(
		windows.PROCESS_SET_QUOTA|windows.PROCESS_TERMINATE, false, uint32(cmd.Process.Pid))
	if err == nil {
		// NOTE: children spawned in the tiny window before this assignment
		// escape the job; in practice a .bat needs longer than this to fork.
		_ = windows.AssignProcessToJobObject(job, h)
		_ = windows.CloseHandle(h)
	}
	return &proc{cmd: cmd, job: job}, nil
}

func newKillOnCloseJob() (windows.Handle, error) {
	job, err := windows.CreateJobObject(nil, nil)
	if err != nil {
		return 0, err
	}
	info := windows.JOBOBJECT_EXTENDED_LIMIT_INFORMATION{
		BasicLimitInformation: windows.JOBOBJECT_BASIC_LIMIT_INFORMATION{
			LimitFlags: windows.JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE,
		},
	}
	_, err = windows.SetInformationJobObject(job,
		windows.JobObjectExtendedLimitInformation,
		uintptr(unsafe.Pointer(&info)), uint32(unsafe.Sizeof(info)))
	if err != nil {
		_ = windows.CloseHandle(job)
		return 0, fmt.Errorf("SetInformationJobObject: %w", err)
	}
	return job, nil
}

// Kill terminates the whole tree (via the job) and the root process.
func (p *proc) Kill() {
	if p.job != 0 {
		_ = windows.CloseHandle(p.job) // KILL_ON_JOB_CLOSE nukes the tree
		p.job = 0
	}
	if p.cmd != nil && p.cmd.Process != nil {
		_ = p.cmd.Process.Kill()
	}
}

// Close releases the job handle without... actually with KILL_ON_JOB_CLOSE
// closing always kills; call it only after the process has exited.
func (p *proc) Close() {
	if p.job != 0 {
		_ = windows.CloseHandle(p.job)
		p.job = 0
	}
}

func (p *proc) Wait() error { return p.cmd.Wait() }
