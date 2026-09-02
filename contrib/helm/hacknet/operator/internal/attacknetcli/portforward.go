package attacknetcli

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"time"
)

const (
	portForwardSchema = "stacks-attacknet-port-forward/v1"
	loopbackAddress   = "127.0.0.1"
)

type portForwardState struct {
	SchemaVersion string            `json:"schemaVersion"`
	Endpoint      DashboardEndpoint `json:"endpoint"`
	LocalPort     int               `json:"localPort"`
	PID           int               `json:"pid"`
	Arguments     []string          `json:"arguments"`
	LogPath       string            `json:"logPath"`
}

type startedPortForward interface {
	PID() int
}

type portForwardRuntime interface {
	Start(string, []string, string) (startedPortForward, error)
	Running(int, []string) (bool, error)
	Terminate(context.Context, int, []string) error
}

type portProbe func(context.Context, string) bool

// OSPortForwardManager owns kubectl processes and portable local state files.
// It verifies the recorded command before signaling a PID so reuse cannot kill
// an unrelated process.
type OSPortForwardManager struct {
	kubectl  string
	stateDir string
	runtime  portForwardRuntime
	probe    portProbe
	now      func() time.Time
}

// NewOSPortForwardManager constructs the production loopback process manager.
func NewOSPortForwardManager(kubectl, stateDir string) *OSPortForwardManager {
	return &OSPortForwardManager{
		kubectl: kubectl, stateDir: stateDir, runtime: osPortForwardRuntime{},
		probe: probeTCP, now: time.Now,
	}
}

// DefaultPortForwardStateDir returns the per-user dashboard process state root.
func DefaultPortForwardStateDir() string {
	if directory, err := os.UserCacheDir(); err == nil && directory != "" {
		return filepath.Join(directory, "stacks-attacknet", "port-forwards")
	}
	return filepath.Join(os.TempDir(), "stacks-attacknet-port-forwards-"+strconv.Itoa(os.Getuid()))
}

// Start launches one background kubectl process and proves its loopback
// listener before returning. Cancellation during startup always cleans it up.
func (manager *OSPortForwardManager) Start(ctx context.Context, request PortForwardRequest) (PortForwardStatus, error) {
	if err := validatePortForwardRequest(request); err != nil {
		return PortForwardStatus{}, err
	}
	release, err := manager.acquire(request.Endpoint.Target)
	if err != nil {
		return PortForwardStatus{}, err
	}
	defer release()

	current, loadErr := manager.load(request.Endpoint.Target)
	if loadErr == nil {
		running, inspectErr := manager.runtime.Running(current.PID, current.Arguments)
		if inspectErr != nil {
			return PortForwardStatus{}, inspectErr
		}
		if running {
			return PortForwardStatus{}, fmt.Errorf("%s dashboard port-forward is already running with PID %d", request.Endpoint.Target, current.PID)
		}
		if err := manager.remove(request.Endpoint.Target); err != nil {
			return PortForwardStatus{}, err
		}
	} else if !errors.Is(loadErr, os.ErrNotExist) {
		return PortForwardStatus{}, loadErr
	}

	if err := os.MkdirAll(manager.stateDir, 0o700); err != nil {
		return PortForwardStatus{}, fmt.Errorf("create port-forward state directory: %w", err)
	}
	address := net.JoinHostPort(loopbackAddress, strconv.Itoa(request.LocalPort))
	if manager.probe(ctx, address) {
		return PortForwardStatus{}, fmt.Errorf("local dashboard port %s is already in use", address)
	}
	logPath := filepath.Join(manager.stateDir, string(request.Endpoint.Target)+".log")
	arguments := portForwardArguments(request)
	process, err := manager.runtime.Start(manager.kubectl, arguments, logPath)
	if err != nil {
		return PortForwardStatus{}, fmt.Errorf("start %s dashboard port-forward: %w", request.Endpoint.Target, err)
	}
	state := portForwardState{
		SchemaVersion: portForwardSchema, Endpoint: request.Endpoint, LocalPort: request.LocalPort,
		PID: process.PID(), Arguments: arguments, LogPath: logPath,
	}
	cleanup := func(cause error) (PortForwardStatus, error) {
		cleanupCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = manager.runtime.Terminate(cleanupCtx, state.PID, state.Arguments)
		_ = manager.remove(state.Endpoint.Target)
		return PortForwardStatus{}, cause
	}
	if err := manager.save(state); err != nil {
		return cleanup(fmt.Errorf("save port-forward state: %w", err))
	}

	deadline := manager.now().Add(request.StartupTimeout)
	for {
		running, inspectErr := manager.runtime.Running(state.PID, state.Arguments)
		if inspectErr != nil {
			return cleanup(inspectErr)
		}
		if !running {
			return cleanup(fmt.Errorf("%s dashboard port-forward exited before listening; see %s", state.Endpoint.Target, state.LogPath))
		}
		if manager.probe(ctx, address) {
			return statusFromState(state, true, true, ""), nil
		}
		if manager.now().After(deadline) {
			return cleanup(fmt.Errorf("%s dashboard port-forward did not listen within %s; see %s", state.Endpoint.Target, request.StartupTimeout, state.LogPath))
		}
		select {
		case <-ctx.Done():
			return cleanup(fmt.Errorf("start %s dashboard port-forward: %w", state.Endpoint.Target, ctx.Err()))
		case <-time.After(50 * time.Millisecond):
		}
	}
}

// Stop terminates only a live process whose command still matches the recorded
// owned port-forward identity.
func (manager *OSPortForwardManager) Stop(ctx context.Context, target DashboardTarget) (PortForwardStatus, error) {
	if _, err := dashboardDefinitionFor(target); err != nil {
		return PortForwardStatus{}, err
	}
	release, err := manager.acquire(target)
	if err != nil {
		return PortForwardStatus{}, err
	}
	defer release()
	state, err := manager.load(target)
	if errors.Is(err, os.ErrNotExist) {
		return stoppedDashboardStatus(target, "no owned port-forward state exists"), nil
	}
	if err != nil {
		return PortForwardStatus{}, err
	}
	running, err := manager.runtime.Running(state.PID, state.Arguments)
	if err != nil {
		return PortForwardStatus{}, err
	}
	if running {
		// Once stop has verified ownership, finish bounded cleanup even if the
		// invoking terminal delivers a second signal.
		cleanupCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 5*time.Second)
		defer cancel()
		if err := manager.runtime.Terminate(cleanupCtx, state.PID, state.Arguments); err != nil {
			return PortForwardStatus{}, err
		}
	}
	if err := manager.remove(target); err != nil {
		return PortForwardStatus{}, err
	}
	detail := "port-forward stopped"
	if !running {
		detail = "stale port-forward state removed"
	}
	return statusFromState(state, false, false, detail), nil
}

// Status inspects local state and the exact recorded process without mutating
// either one.
func (manager *OSPortForwardManager) Status(ctx context.Context, target DashboardTarget) (PortForwardStatus, error) {
	if _, err := dashboardDefinitionFor(target); err != nil {
		return PortForwardStatus{}, err
	}
	state, err := manager.load(target)
	if errors.Is(err, os.ErrNotExist) {
		return stoppedDashboardStatus(target, "no owned port-forward state exists"), nil
	}
	if err != nil {
		return PortForwardStatus{}, err
	}
	running, err := manager.runtime.Running(state.PID, state.Arguments)
	if err != nil {
		return PortForwardStatus{}, err
	}
	ready := false
	detail := "recorded process is not running"
	if running {
		address := net.JoinHostPort(loopbackAddress, strconv.Itoa(state.LocalPort))
		ready = manager.probe(ctx, address)
		detail = "port-forward process is starting"
		if ready {
			detail = ""
		}
	}
	return statusFromState(state, running, ready, detail), nil
}

func validatePortForwardRequest(request PortForwardRequest) error {
	if _, err := dashboardDefinitionFor(request.Endpoint.Target); err != nil {
		return err
	}
	if request.Endpoint.Namespace == "" || request.Endpoint.Service == "" || request.Endpoint.RemotePort < 1 || request.Endpoint.RemotePort > 65535 {
		return errors.New("dashboard endpoint is incomplete")
	}
	if request.LocalPort < 1024 || request.LocalPort > 65535 {
		return errors.New("local port must be between 1024 and 65535")
	}
	if request.StartupTimeout <= 0 || request.StartupTimeout > time.Minute {
		return errors.New("startup timeout must be greater than zero and at most one minute")
	}
	return nil
}

func portForwardArguments(request PortForwardRequest) []string {
	return []string{
		"--namespace", request.Endpoint.Namespace, "port-forward", "service/" + request.Endpoint.Service,
		fmt.Sprintf("%d:%d", request.LocalPort, request.Endpoint.RemotePort), "--address=" + loopbackAddress,
	}
}

func statusFromState(state portForwardState, running, ready bool, detail string) PortForwardStatus {
	return PortForwardStatus{
		SchemaVersion: portForwardSchema, Target: state.Endpoint.Target, Namespace: state.Endpoint.Namespace,
		Service: state.Endpoint.Service, LocalAddress: loopbackAddress, LocalPort: state.LocalPort,
		RemotePort: state.Endpoint.RemotePort, PID: state.PID, Running: running, Ready: ready,
		URL: fmt.Sprintf("http://%s:%d", loopbackAddress, state.LocalPort), LogPath: state.LogPath, Detail: detail,
	}
}

func stoppedDashboardStatus(target DashboardTarget, detail string) PortForwardStatus {
	definition, _ := dashboardDefinitionFor(target)
	return PortForwardStatus{
		SchemaVersion: portForwardSchema, Target: target, LocalAddress: loopbackAddress,
		LocalPort: definition.defaultLocalPort, Running: false, Ready: false,
		URL: fmt.Sprintf("http://%s:%d", loopbackAddress, definition.defaultLocalPort), Detail: detail,
	}
}

func (manager *OSPortForwardManager) statePath(target DashboardTarget) string {
	return filepath.Join(manager.stateDir, string(target)+".json")
}

func (manager *OSPortForwardManager) load(target DashboardTarget) (portForwardState, error) {
	data, err := os.ReadFile(manager.statePath(target))
	if err != nil {
		return portForwardState{}, err
	}
	var state portForwardState
	if err := json.Unmarshal(data, &state); err != nil {
		return portForwardState{}, fmt.Errorf("decode %s port-forward state: %w", target, err)
	}
	if state.SchemaVersion != portForwardSchema || state.Endpoint.Target != target || state.PID <= 0 || len(state.Arguments) == 0 {
		return portForwardState{}, fmt.Errorf("%s port-forward state is invalid", target)
	}
	return state, nil
}

func (manager *OSPortForwardManager) save(state portForwardState) error {
	if err := os.MkdirAll(manager.stateDir, 0o700); err != nil {
		return err
	}
	data, err := json.MarshalIndent(state, "", "  ")
	if err != nil {
		return err
	}
	data = append(data, '\n')
	return os.WriteFile(manager.statePath(state.Endpoint.Target), data, 0o600)
}

func (manager *OSPortForwardManager) remove(target DashboardTarget) error {
	err := os.Remove(manager.statePath(target))
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	return err
}

func (manager *OSPortForwardManager) acquire(target DashboardTarget) (func(), error) {
	if err := os.MkdirAll(manager.stateDir, 0o700); err != nil {
		return nil, err
	}
	path := filepath.Join(manager.stateDir, string(target)+".lock")
	for attempt := 0; attempt < 2; attempt++ {
		file, err := os.OpenFile(path, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600)
		if err == nil {
			if _, writeErr := fmt.Fprintf(file, "%d\n", os.Getpid()); writeErr != nil {
				_ = file.Close()
				_ = os.Remove(path)
				return nil, writeErr
			}
			if closeErr := file.Close(); closeErr != nil {
				_ = os.Remove(path)
				return nil, closeErr
			}
			return func() { _ = os.Remove(path) }, nil
		}
		if !errors.Is(err, os.ErrExist) {
			return nil, err
		}
		owner, readErr := os.ReadFile(path)
		pid, parseErr := strconv.Atoi(strings.TrimSpace(string(owner)))
		if readErr != nil || parseErr != nil || !processExists(pid) {
			if removeErr := os.Remove(path); removeErr != nil && !errors.Is(removeErr, os.ErrNotExist) {
				return nil, removeErr
			}
			continue
		}
		return nil, fmt.Errorf("%s dashboard port-forward operation is already in progress by PID %d", target, pid)
	}
	return nil, fmt.Errorf("could not acquire %s dashboard port-forward operation lock", target)
}

func processExists(pid int) bool {
	if pid <= 0 {
		return false
	}
	process, err := os.FindProcess(pid)
	return err == nil && process.Signal(syscall.Signal(0)) == nil
}

func probeTCP(ctx context.Context, address string) bool {
	dialer := net.Dialer{Timeout: 200 * time.Millisecond}
	connection, err := dialer.DialContext(ctx, "tcp", address)
	if err != nil {
		return false
	}
	_ = connection.Close()
	return true
}

type osStartedPortForward struct{ process *os.Process }

func (process osStartedPortForward) PID() int { return process.process.Pid }

type osPortForwardRuntime struct{}

func (osPortForwardRuntime) Start(binary string, arguments []string, logPath string) (startedPortForward, error) {
	resolved, err := exec.LookPath(binary)
	if err != nil {
		return nil, fmt.Errorf("find %s: %w", binary, err)
	}
	log, err := os.OpenFile(logPath, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o600)
	if err != nil {
		return nil, err
	}
	defer log.Close()
	command := exec.Command(resolved, arguments...)
	command.Stdin = nil
	command.Stdout = log
	command.Stderr = log
	// The port-forward is intentionally longer-lived than this CLI invocation.
	// Give it an independent session so terminal exit and job-control signals do
	// not silently tear down a dashboard that Start already reported as ready.
	command.SysProcAttr = &syscall.SysProcAttr{Setsid: true}
	if err := command.Start(); err != nil {
		return nil, err
	}
	// Reap early failures while the CLI process is still alive. Once a
	// successful background start returns, normal parent exit reparents the
	// long-running kubectl process to the host process supervisor.
	go func() { _ = command.Wait() }()
	return osStartedPortForward{process: command.Process}, nil
}

func (osPortForwardRuntime) Running(pid int, arguments []string) (bool, error) {
	process, err := os.FindProcess(pid)
	if err != nil {
		return false, nil
	}
	if err := process.Signal(syscall.Signal(0)); err != nil {
		return false, nil
	}
	output, err := exec.Command("ps", "-p", strconv.Itoa(pid), "-o", "command=").Output()
	if err != nil {
		return false, nil
	}
	commandLine := strings.TrimSpace(string(output))
	expected := strings.Join(arguments, " ")
	if !strings.Contains(commandLine, expected) {
		return false, fmt.Errorf("refusing process %d: command does not match owned port-forward", pid)
	}
	return true, nil
}

func (runtime osPortForwardRuntime) Terminate(ctx context.Context, pid int, arguments []string) error {
	running, err := runtime.Running(pid, arguments)
	if err != nil {
		return err
	}
	if !running {
		return nil
	}
	process, err := os.FindProcess(pid)
	if err != nil {
		return nil
	}
	if err := process.Signal(syscall.SIGTERM); err != nil && !errors.Is(err, os.ErrProcessDone) {
		return err
	}
	ticker := time.NewTicker(50 * time.Millisecond)
	defer ticker.Stop()
	deadline := time.NewTimer(5 * time.Second)
	defer deadline.Stop()
	for {
		running, inspectErr := runtime.Running(pid, arguments)
		if inspectErr != nil || !running {
			return inspectErr
		}
		select {
		case <-ctx.Done():
			_ = process.Signal(os.Kill)
			return ctx.Err()
		case <-deadline.C:
			if err := process.Signal(os.Kill); err != nil && !errors.Is(err, os.ErrProcessDone) {
				return err
			}
			return nil
		case <-ticker.C:
		}
	}
}
