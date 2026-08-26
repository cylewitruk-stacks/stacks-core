package attacknetcli

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"os/exec"
)

// Command is one exact executable invocation. Arguments are never interpreted
// by a shell.
type Command struct {
	Program string
	Args    []string
	Stdin   io.Reader
}

// CommandResult contains the captured output of one process invocation.
type CommandResult struct {
	Stdout string
	Stderr string
}

// CommandRunner executes external tools through an explicit argv boundary.
type CommandRunner interface {
	Run(context.Context, Command) (CommandResult, error)
}

// ProcessError reports a failed external command without losing its stderr.
type ProcessError struct {
	Command Command
	Result  CommandResult
	Cause   error
}

func (err *ProcessError) Error() string {
	return fmt.Sprintf("run %s: %v: %s", err.Command.Program, err.Cause, err.Result.Stderr)
}

// Unwrap exposes the process exit error.
func (err *ProcessError) Unwrap() error { return err.Cause }

// ExecCommandRunner executes commands using os/exec and context cancellation.
type ExecCommandRunner struct{}

// Run executes one command without invoking a shell.
func (ExecCommandRunner) Run(ctx context.Context, command Command) (CommandResult, error) {
	if command.Program == "" {
		return CommandResult{}, fmt.Errorf("command program is required")
	}
	process := exec.CommandContext(ctx, command.Program, command.Args...)
	process.Stdin = command.Stdin
	var stdout bytes.Buffer
	var stderr bytes.Buffer
	process.Stdout = &stdout
	process.Stderr = &stderr
	err := process.Run()
	result := CommandResult{Stdout: stdout.String(), Stderr: stderr.String()}
	if err != nil {
		return result, &ProcessError{Command: command, Result: result, Cause: err}
	}
	return result, nil
}
