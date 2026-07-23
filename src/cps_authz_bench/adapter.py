"""Bounded subprocess adapter for arbitrary authorization analyzers."""

from __future__ import annotations

import base64
import math
import os
import signal
import subprocess
import threading
import time
from dataclasses import dataclass
from numbers import Integral, Real
from os import PathLike
from pathlib import Path
from typing import Any, Mapping, Sequence

from .json_boundary import parse_analyzer_output


MAX_TIMEOUT_SECONDS = 300.0
MAX_OUTPUT_BYTES = 16 * 1024 * 1024
_PROCESS_CLEANUP_SECONDS = 2.0
_CREATE_SUSPENDED = 0x00000004
_JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE = 0x00002000
_JOB_OBJECT_EXTENDED_LIMIT_INFORMATION = 9
_TH32CS_SNAPTHREAD = 0x00000004
_THREAD_SUSPEND_RESUME = 0x0002
_INVALID_DWORD = 0xFFFFFFFF
_INVALID_UTF8_PREFIX = "invalid-utf8-base64:"


@dataclass(frozen=True)
class OutputCapture:
    """An injective, explicitly tagged representation of captured bytes."""

    encoding: str
    data: str

    def __post_init__(self) -> None:
        if self.encoding == "utf-8":
            try:
                self.data.encode("utf-8", errors="strict")
            except (AttributeError, UnicodeEncodeError) as exc:
                raise ValueError("UTF-8 capture data must be Unicode scalar text") from exc
            return
        if self.encoding == "base64":
            if not isinstance(self.data, str):
                raise ValueError("base64 capture data must be a string")
            try:
                raw = base64.b64decode(self.data, validate=True)
            except (ValueError, TypeError) as exc:
                raise ValueError("base64 capture data must be canonical") from exc
            if base64.b64encode(raw).decode("ascii") != self.data:
                raise ValueError("base64 capture data must be canonical")
            return
        raise ValueError("capture encoding must be 'utf-8' or 'base64'")

    @classmethod
    def from_bytes(cls, value: bytes) -> "OutputCapture":
        try:
            return cls("utf-8", value.decode("utf-8", errors="strict"))
        except UnicodeDecodeError:
            return cls("base64", base64.b64encode(value).decode("ascii"))

    def raw_bytes(self) -> bytes:
        if self.encoding == "utf-8":
            return self.data.encode("utf-8", errors="strict")
        return base64.b64decode(self.data, validate=True)

    def display_text(self) -> str:
        if self.encoding == "utf-8":
            return self.data
        return _INVALID_UTF8_PREFIX + self.data

    def to_dict(self) -> dict[str, str]:
        return {"encoding": self.encoding, "data": self.data}


@dataclass(frozen=True)
class ToolExecution:
    """Normalized outcome of one external analyzer invocation."""

    status: str
    exit_code: int | None
    findings: tuple[dict[str, Any], ...] | None
    stdout: str
    stderr: str
    error: str | None = None
    stdout_capture: OutputCapture | None = None
    stderr_capture: OutputCapture | None = None

    def __post_init__(self) -> None:
        stdout_capture = self.stdout_capture or OutputCapture("utf-8", self.stdout)
        stderr_capture = self.stderr_capture or OutputCapture("utf-8", self.stderr)
        if self.stdout != stdout_capture.display_text():
            raise ValueError("stdout display must match its tagged byte capture")
        if self.stderr != stderr_capture.display_text():
            raise ValueError("stderr display must match its tagged byte capture")
        object.__setattr__(self, "stdout_capture", stdout_capture)
        object.__setattr__(self, "stderr_capture", stderr_capture)

    def to_dict(self) -> dict[str, Any]:
        return {
            "status": self.status,
            "exit_code": self.exit_code,
            "findings": None if self.findings is None else [dict(item) for item in self.findings],
            "stdout": self.stdout_capture.to_dict(),
            "stderr": self.stderr_capture.to_dict(),
            "error": self.error,
        }


def _captured(value: bytes) -> tuple[str, OutputCapture]:
    capture = OutputCapture.from_bytes(value)
    return capture.display_text(), capture


def _validated_timeout(value: object) -> float:
    if isinstance(value, bool) or not isinstance(value, Real):
        raise ValueError("timeout_seconds must be a finite real number")
    try:
        finite = math.isfinite(value)
    except (OverflowError, TypeError, ValueError):
        finite = False
    if not finite:
        raise ValueError("timeout_seconds must be a finite real number")
    if value <= 0:
        raise ValueError("timeout_seconds must be positive")
    if value > MAX_TIMEOUT_SECONDS:
        raise ValueError(f"timeout_seconds must be at most {MAX_TIMEOUT_SECONDS:g}")
    return float(value)


def _validated_output_limit(value: object) -> int:
    if isinstance(value, bool) or not isinstance(value, Integral):
        raise ValueError("max_output_bytes must be a finite integer")
    normalized = int(value)
    if normalized < 1:
        raise ValueError("max_output_bytes must be positive")
    if normalized > MAX_OUTPUT_BYTES:
        raise ValueError(f"max_output_bytes must be at most {MAX_OUTPUT_BYTES}")
    return normalized


class _WindowsContainmentError(RuntimeError):
    """A Windows analyzer could not be contained before its first instruction."""


class _WindowsJob:
    """Kill-on-close Job Object assigned while the analyzer is suspended."""

    def __init__(self, kernel32: Any, handle: Any) -> None:
        self._kernel32 = kernel32
        self._handle = handle

    @classmethod
    def attach(cls, process: subprocess.Popen[bytes]) -> "_WindowsJob | None":
        if os.name != "nt":
            return None
        import ctypes
        from ctypes import wintypes

        class BasicLimitInformation(ctypes.Structure):
            _fields_ = [
                ("PerProcessUserTimeLimit", ctypes.c_longlong),
                ("PerJobUserTimeLimit", ctypes.c_longlong),
                ("LimitFlags", wintypes.DWORD),
                ("MinimumWorkingSetSize", ctypes.c_size_t),
                ("MaximumWorkingSetSize", ctypes.c_size_t),
                ("ActiveProcessLimit", wintypes.DWORD),
                ("Affinity", ctypes.c_size_t),
                ("PriorityClass", wintypes.DWORD),
                ("SchedulingClass", wintypes.DWORD),
            ]

        class IOCounters(ctypes.Structure):
            _fields_ = [
                ("ReadOperationCount", ctypes.c_ulonglong),
                ("WriteOperationCount", ctypes.c_ulonglong),
                ("OtherOperationCount", ctypes.c_ulonglong),
                ("ReadTransferCount", ctypes.c_ulonglong),
                ("WriteTransferCount", ctypes.c_ulonglong),
                ("OtherTransferCount", ctypes.c_ulonglong),
            ]

        class ExtendedLimitInformation(ctypes.Structure):
            _fields_ = [
                ("BasicLimitInformation", BasicLimitInformation),
                ("IoInfo", IOCounters),
                ("ProcessMemoryLimit", ctypes.c_size_t),
                ("JobMemoryLimit", ctypes.c_size_t),
                ("PeakProcessMemoryUsed", ctypes.c_size_t),
                ("PeakJobMemoryUsed", ctypes.c_size_t),
            ]

        kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
        kernel32.CreateJobObjectW.argtypes = [ctypes.c_void_p, wintypes.LPCWSTR]
        kernel32.CreateJobObjectW.restype = wintypes.HANDLE
        kernel32.SetInformationJobObject.argtypes = [
            wintypes.HANDLE,
            ctypes.c_int,
            ctypes.c_void_p,
            wintypes.DWORD,
        ]
        kernel32.SetInformationJobObject.restype = wintypes.BOOL
        kernel32.AssignProcessToJobObject.argtypes = [wintypes.HANDLE, wintypes.HANDLE]
        kernel32.AssignProcessToJobObject.restype = wintypes.BOOL
        kernel32.TerminateJobObject.argtypes = [wintypes.HANDLE, wintypes.UINT]
        kernel32.TerminateJobObject.restype = wintypes.BOOL
        kernel32.CloseHandle.argtypes = [wintypes.HANDLE]
        kernel32.CloseHandle.restype = wintypes.BOOL

        handle = kernel32.CreateJobObjectW(None, None)
        if not handle:
            error_code = ctypes.get_last_error()
            raise _WindowsContainmentError(
                f"CreateJobObjectW failed with Windows error {error_code}"
            )

        keep_handle = False
        try:
            information = ExtendedLimitInformation()
            information.BasicLimitInformation.LimitFlags = (
                _JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE
            )
            if not kernel32.SetInformationJobObject(
                handle,
                _JOB_OBJECT_EXTENDED_LIMIT_INFORMATION,
                ctypes.byref(information),
                ctypes.sizeof(information),
            ):
                error_code = ctypes.get_last_error()
                raise _WindowsContainmentError(
                    "SetInformationJobObject failed with Windows error "
                    f"{error_code}"
                )
            if not kernel32.AssignProcessToJobObject(
                handle, wintypes.HANDLE(process._handle)  # type: ignore[attr-defined]
            ):
                error_code = ctypes.get_last_error()
                raise _WindowsContainmentError(
                    "AssignProcessToJobObject failed with Windows error "
                    f"{error_code}"
                )
            keep_handle = True
            return cls(kernel32, handle)
        finally:
            if not keep_handle:
                kernel32.CloseHandle(handle)

    def resume(self, process: subprocess.Popen[bytes]) -> None:
        """Resume the sole primary thread after Job assignment."""

        import ctypes
        from ctypes import wintypes

        class ThreadEntry32(ctypes.Structure):
            _fields_ = [
                ("dwSize", wintypes.DWORD),
                ("cntUsage", wintypes.DWORD),
                ("th32ThreadID", wintypes.DWORD),
                ("th32OwnerProcessID", wintypes.DWORD),
                ("tpBasePri", wintypes.LONG),
                ("tpDeltaPri", wintypes.LONG),
                ("dwFlags", wintypes.DWORD),
            ]

        kernel32 = self._kernel32
        kernel32.CreateToolhelp32Snapshot.argtypes = [
            wintypes.DWORD,
            wintypes.DWORD,
        ]
        kernel32.CreateToolhelp32Snapshot.restype = wintypes.HANDLE
        kernel32.Thread32First.argtypes = [
            wintypes.HANDLE,
            ctypes.POINTER(ThreadEntry32),
        ]
        kernel32.Thread32First.restype = wintypes.BOOL
        kernel32.Thread32Next.argtypes = [
            wintypes.HANDLE,
            ctypes.POINTER(ThreadEntry32),
        ]
        kernel32.Thread32Next.restype = wintypes.BOOL
        kernel32.OpenThread.argtypes = [
            wintypes.DWORD,
            wintypes.BOOL,
            wintypes.DWORD,
        ]
        kernel32.OpenThread.restype = wintypes.HANDLE
        kernel32.ResumeThread.argtypes = [wintypes.HANDLE]
        kernel32.ResumeThread.restype = wintypes.DWORD

        snapshot = kernel32.CreateToolhelp32Snapshot(_TH32CS_SNAPTHREAD, 0)
        if snapshot == wintypes.HANDLE(-1).value:
            error_code = ctypes.get_last_error()
            raise _WindowsContainmentError(
                "CreateToolhelp32Snapshot failed with Windows error "
                f"{error_code}"
            )

        thread_handle = None
        try:
            entry = ThreadEntry32()
            entry.dwSize = ctypes.sizeof(entry)
            has_entry = kernel32.Thread32First(snapshot, ctypes.byref(entry))
            while has_entry:
                if entry.th32OwnerProcessID == process.pid:
                    thread_handle = kernel32.OpenThread(
                        _THREAD_SUSPEND_RESUME,
                        False,
                        entry.th32ThreadID,
                    )
                    if not thread_handle:
                        error_code = ctypes.get_last_error()
                        raise _WindowsContainmentError(
                            f"OpenThread failed with Windows error {error_code}"
                        )
                    break
                has_entry = kernel32.Thread32Next(snapshot, ctypes.byref(entry))
            if thread_handle is None:
                raise _WindowsContainmentError(
                    "could not locate the suspended analyzer thread"
                )
        finally:
            kernel32.CloseHandle(snapshot)

        try:
            previous_suspend_count = kernel32.ResumeThread(thread_handle)
            if previous_suspend_count == _INVALID_DWORD:
                error_code = ctypes.get_last_error()
                raise _WindowsContainmentError(
                    f"ResumeThread failed with Windows error {error_code}"
                )
            if previous_suspend_count != 1:
                raise _WindowsContainmentError(
                    "ResumeThread returned unexpected suspend count "
                    f"{previous_suspend_count}"
                )
        finally:
            kernel32.CloseHandle(thread_handle)

    def terminate(self) -> None:
        if self._handle is not None:
            self._kernel32.TerminateJobObject(self._handle, 1)

    def close(self) -> None:
        if self._handle is not None:
            self._kernel32.CloseHandle(self._handle)
            self._handle = None


def _terminate_process_tree(
    process: subprocess.Popen[bytes], windows_job: _WindowsJob | None
) -> None:
    """Best-effort force termination of the analyzer process group and descendants."""

    if windows_job is not None:
        windows_job.terminate()
    elif os.name == "nt":
        try:
            subprocess.run(
                ["taskkill", "/PID", str(process.pid), "/T", "/F"],
                stdin=subprocess.DEVNULL,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                timeout=_PROCESS_CLEANUP_SECONDS,
                check=False,
                shell=False,
            )
        except (OSError, subprocess.SubprocessError):
            pass
    else:
        try:
            os.killpg(process.pid, signal.SIGKILL)
        except (OSError, ProcessLookupError):
            pass
    if process.poll() is None:
        try:
            process.kill()
        except OSError:
            pass


def _abort_windows_launch(
    process: subprocess.Popen[bytes], windows_job: _WindowsJob | None
) -> None:
    """Dispose of a process that must not continue after containment failure."""

    if windows_job is not None:
        windows_job.terminate()
    if process.poll() is None:
        try:
            process.kill()
        except OSError:
            pass
    try:
        process.wait(timeout=_PROCESS_CLEANUP_SECONDS)
    except subprocess.TimeoutExpired:
        if windows_job is not None:
            windows_job.terminate()
        try:
            process.kill()
        except OSError:
            pass
        try:
            process.wait(timeout=_PROCESS_CLEANUP_SECONDS)
        except subprocess.TimeoutExpired:
            pass
    for stream in (process.stdin, process.stdout, process.stderr):
        if stream is not None:
            try:
                stream.close()
            except OSError:
                pass
    if windows_job is not None:
        windows_job.close()


def run_tool(
    command: Sequence[str | PathLike[str]],
    payload: bytes,
    *,
    timeout_seconds: float = 2.0,
    max_output_bytes: int = 1_000_000,
    cwd: str | Path | None = None,
    environment: Mapping[str, str] | None = None,
) -> ToolExecution:
    """Run an analyzer with payload on stdin and bounded combined output.

    The analyzer must emit one UTF-8 JSON object containing a ``findings`` array.
    Commands are executed directly with ``shell=False``.
    """

    if isinstance(command, (str, bytes)) or not command:
        raise ValueError("command must be a non-empty argument sequence")
    timeout_seconds = _validated_timeout(timeout_seconds)
    max_output_bytes = _validated_output_limit(max_output_bytes)

    process_options: dict[str, Any] = {}
    if os.name == "nt":
        process_options["creationflags"] = (
            subprocess.CREATE_NEW_PROCESS_GROUP | _CREATE_SUSPENDED
        )
    else:
        process_options["start_new_session"] = True

    try:
        process = subprocess.Popen(
            [str(item) for item in command],
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            cwd=None if cwd is None else str(cwd),
            env=None if environment is None else dict(environment),
            shell=False,
            **process_options,
        )
    except OSError as error:
        return ToolExecution("launch_error", None, None, "", "", str(error))

    windows_job = None
    if os.name == "nt":
        try:
            windows_job = _WindowsJob.attach(process)
            if windows_job is None:
                raise _WindowsContainmentError(
                    "Job Object setup returned no containment handle"
                )
            windows_job.resume(process)
        except Exception as error:
            _abort_windows_launch(process, windows_job)
            detail = (
                str(error)
                if isinstance(error, _WindowsContainmentError)
                else type(error).__name__
            )
            return ToolExecution(
                "launch_error",
                None,
                None,
                "",
                "",
                "failed to establish Windows process containment: " + detail,
            )

    stdout_data = bytearray()
    stderr_data = bytearray()
    output_total = 0
    output_lock = threading.Lock()
    overflow = threading.Event()
    stdout_done = threading.Event()
    stderr_done = threading.Event()
    stdin_done = threading.Event()

    def read_stream(
        stream: Any, destination: bytearray, completed: threading.Event
    ) -> None:
        nonlocal output_total
        try:
            while True:
                try:
                    chunk = stream.read(4096)
                except OSError:
                    return
                if not chunk:
                    return
                with output_lock:
                    remaining = max(0, max_output_bytes - output_total)
                    destination.extend(chunk[:remaining])
                    output_total += len(chunk)
                    if output_total > max_output_bytes:
                        overflow.set()
        finally:
            try:
                stream.close()
            finally:
                completed.set()

    def write_stdin() -> None:
        try:
            if process.stdin is not None:
                process.stdin.write(payload)
                process.stdin.flush()
        except (BrokenPipeError, OSError):
            pass
        finally:
            if process.stdin is not None:
                try:
                    process.stdin.close()
                finally:
                    stdin_done.set()
            else:
                stdin_done.set()

    readers = [
        threading.Thread(
            target=read_stream,
            args=(process.stdout, stdout_data, stdout_done),
            daemon=True,
        ),
        threading.Thread(
            target=read_stream,
            args=(process.stderr, stderr_data, stderr_done),
            daemon=True,
        ),
    ]
    writer = threading.Thread(target=write_stdin, daemon=True)
    for thread in readers:
        thread.start()
    writer.start()

    deadline = time.monotonic() + timeout_seconds
    forced_status: str | None = None
    while True:
        if overflow.is_set():
            forced_status = "output_limit"
            _terminate_process_tree(process, windows_job)
            break
        if time.monotonic() >= deadline:
            forced_status = "timeout"
            _terminate_process_tree(process, windows_job)
            break
        if (
            process.poll() is not None
            and stdout_done.is_set()
            and stderr_done.is_set()
            and stdin_done.is_set()
        ):
            break
        time.sleep(0.005)
    try:
        process.wait(timeout=_PROCESS_CLEANUP_SECONDS)
    except subprocess.TimeoutExpired:
        _terminate_process_tree(process, windows_job)
        process.wait(timeout=_PROCESS_CLEANUP_SECONDS)
    writer.join(timeout=_PROCESS_CLEANUP_SECONDS)
    for thread in readers:
        thread.join(timeout=_PROCESS_CLEANUP_SECONDS)
    if windows_job is not None:
        windows_job.close()

    stdout, stdout_capture = _captured(bytes(stdout_data))
    stderr, stderr_capture = _captured(bytes(stderr_data))
    if forced_status == "timeout":
        return ToolExecution(
            "timeout",
            None,
            None,
            stdout,
            stderr,
            "tool exceeded timeout",
            stdout_capture,
            stderr_capture,
        )
    if forced_status == "output_limit" or overflow.is_set():
        return ToolExecution(
            "output_limit",
            process.returncode,
            None,
            stdout,
            stderr,
            f"combined output exceeded {max_output_bytes} bytes",
            stdout_capture,
            stderr_capture,
        )
    if process.returncode != 0:
        return ToolExecution(
            "tool_error",
            process.returncode,
            None,
            stdout,
            stderr,
            f"tool exited with code {process.returncode}",
            stdout_capture,
            stderr_capture,
        )
    try:
        findings = parse_analyzer_output(stdout_data)
    except ValueError as error:
        return ToolExecution(
            "malformed_output",
            process.returncode,
            None,
            stdout,
            stderr,
            str(error),
            stdout_capture,
            stderr_capture,
        )
    return ToolExecution(
        "ok",
        process.returncode,
        findings,
        stdout,
        stderr,
        None,
        stdout_capture,
        stderr_capture,
    )
