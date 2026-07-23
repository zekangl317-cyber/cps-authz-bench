# Security policy

## Supported versions

Security fixes are applied to the latest released minor version. The current
development line is 0.1.x.

## Reporting a vulnerability

Use the repository host's private security-advisory mechanism when available.
Avoid public disclosure of a working command-injection, resource-exhaustion, or
path-traversal reproducer until a fix is available. Include a minimal synthetic
case, affected version, platform, impact, and mitigation.

## Executing analyzers safely

The subprocess adapter passes an argument list to `subprocess.Popen` with
`shell=False`, limits wall time and combined output, and validates stdout. On
Windows it creates the analyzer suspended and assigns a configured
kill-on-close Job Object before resuming it; containment setup failure is
fail-closed. It is not a sandbox. An analyzer runs with the invoking user's
filesystem, process, and network permissions and may spawn descendants. Only
run analyzers you trust, or place the entire benchmark process inside an
isolation boundary selected and managed by your organization.

Case payloads, tool output, corpus files, and JSONL records are untrusted data.
Do not place secrets in benchmark inputs. Corpus directories may preserve tool
stderr and should be handled according to the analyzer's data sensitivity.
Mutation inputs may choose IDs that match the generator's preferred synthetic
IDs or may already contain oracle findings. Mutation ID allocation checks the
corresponding effect or request namespace, and both the API and CLI require the
recomputed result to be exactly the requested mutation's one finding before a
case is returned or written. This protects benchmark labeling; it does not make
an analyzer or its input trustworthy.

JSONL records are framed only by LF. CRLF is accepted as JSON followed by a CR
whitespace character and LF delimiter, while bare CR does not delimit records.
Literal U+2028 and U+2029 are preserved as string data rather than treated as
record boundaries.

Bounded finding text rejects C0/C1 controls but deliberately preserves Unicode
format characters, including bidirectional controls; user interfaces and logs
should isolate or escape these untrusted strings when visual ordering matters.
