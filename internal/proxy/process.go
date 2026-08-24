package proxy

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"sync"
	"syscall"
	"time"
)

// ProcessSupervisor manages the lifecycle of a downstream MCP subprocess
type ProcessSupervisor struct {
	command    string
	args       []string
	env        map[string]string
	workingDir string

	cmd    *exec.Cmd
	stdin  io.WriteCloser
	stdout io.ReadCloser
	stderr io.ReadCloser

	mu      sync.Mutex
	running bool
}

// NewProcessSupervisor creates a supervisor for the specified downstream command
func NewProcessSupervisor(command string, args []string, env map[string]string, workingDir string) *ProcessSupervisor {
	return &ProcessSupervisor{
		command:    command,
		args:       args,
		env:        env,
		workingDir: workingDir,
	}
}

// Start launches the downstream subprocess and returns its stdio pipes
func (s *ProcessSupervisor) Start(ctx context.Context) (io.WriteCloser, io.ReadCloser, io.ReadCloser, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	if s.running {
		return nil, nil, nil, fmt.Errorf("process is already running")
	}

	if s.command == "" {
		return nil, nil, nil, fmt.Errorf("downstream command cannot be empty")
	}

	s.cmd = exec.CommandContext(ctx, s.command, s.args...)
	if s.workingDir != "" {
		s.cmd.Dir = s.workingDir
	}

	// Inherit system environment and append custom environment variables
	s.cmd.Env = os.Environ()
	for k, v := range s.env {
		s.cmd.Env = append(s.cmd.Env, fmt.Sprintf("%s=%s", k, v))
	}

	var err error
	s.stdin, err = s.cmd.StdinPipe()
	if err != nil {
		return nil, nil, nil, fmt.Errorf("failed to create stdin pipe: %w", err)
	}

	s.stdout, err = s.cmd.StdoutPipe()
	if err != nil {
		_ = s.stdin.Close()
		return nil, nil, nil, fmt.Errorf("failed to create stdout pipe: %w", err)
	}

	s.stderr, err = s.cmd.StderrPipe()
	if err != nil {
		_ = s.stdin.Close()
		_ = s.stdout.Close()
		return nil, nil, nil, fmt.Errorf("failed to create stderr pipe: %w", err)
	}

	if err := s.cmd.Start(); err != nil {
		_ = s.stdin.Close()
		_ = s.stdout.Close()
		_ = s.stderr.Close()
		return nil, nil, nil, fmt.Errorf("failed to start downstream process '%s': %w", s.command, err)
	}

	s.running = true
	return s.stdin, s.stdout, s.stderr, nil
}

// Wait waits for the downstream command to exit
func (s *ProcessSupervisor) Wait() error {
	s.mu.Lock()
	cmd := s.cmd
	s.mu.Unlock()

	if cmd == nil {
		return nil
	}

	err := cmd.Wait()

	s.mu.Lock()
	s.running = false
	s.mu.Unlock()

	return err
}

// Stop gracefully terminates the subprocess, escalating to SIGKILL if necessary
func (s *ProcessSupervisor) Stop() error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if !s.running || s.cmd == nil || s.cmd.Process == nil {
		return nil
	}

	// Close stdin to notify subprocess of EOF
	if s.stdin != nil {
		_ = s.stdin.Close()
	}

	// Send SIGTERM
	_ = s.cmd.Process.Signal(syscall.SIGTERM)

	// Wait up to 2 seconds for graceful termination
	done := make(chan error, 1)
	go func() {
		done <- s.cmd.Wait()
	}()

	select {
	case err := <-done:
		s.running = false
		if isNormalTermination(err) {
			return nil
		}
		return err
	case <-time.After(2 * time.Second):
		// Force kill
		_ = s.cmd.Process.Kill()
		s.running = false
		return nil
	}
}

func isNormalTermination(err error) bool {
	if err == nil {
		return true
	}
	var exitErr *exec.ExitError
	if errors.As(err, &exitErr) {
		// Terminated by signal (SIGTERM, SIGKILL, SIGHUP)
		if status, ok := exitErr.Sys().(syscall.WaitStatus); ok {
			if status.Signaled() {
				return true
			}
		}
	}
	return false
}

// IsRunning returns whether the subprocess is currently active
func (s *ProcessSupervisor) IsRunning() bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.running
}
