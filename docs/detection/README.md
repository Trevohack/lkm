# Detection & forensic reference 


> [!Important]
> Do **not** run any kernel experiments on production systems. Use isolated, instrumented lab hosts and retain immutable forensic copies (pcaps, `/proc` dumps, logs) for offline analysis.

---

## Quick guidance — how to use this file

1. Treat the listed paths as **observation surfaces**: they are places where a kernel-interfering component will often leave side effects or where its presence becomes observable when compared to external sources.
2. Collect artifacts (copies of files, kernel logs, pcaps) and **triangulate** using multiple independent sources (external packet capture, netflow, separate host snapshots).
3. Prefer read-only inspections and remote captures—avoid running untrusted code or utilities that could be tampered with on the suspect host.

---

## Paths & explanations

Below are grouped file paths you should check, with why they matter and simple, safe example commands to inspect them.

### Tracing Filter Functions

**Paths**

```
/sys/kernel/tracing/available_filter_functions
/sys/debug/kernel/tracing/available_filter_functions
/sys/kernel/tracing/available_filter_functions_addrs
/sys/debug/kernel/tracing/available_filter_functions_addrs
/sys/kernel/tracing/enabled_functions
/sys/debug/kernel/tracing/enabled_functions
/sys/kernel/tracing/touched_functions
/sys/kernel/tracing/kprobe_events
```

**Why check these**
The kernel tracing subsystem (ftrace, kprobes, tracefs) exposes available tracing points and active probes. A kernel component that wants to hide itself or cover traces may tamper with these files or the underlying lists of available/enabled functions. Missing entries, modified addresses, or unexpected probe entries are indicators.

**What to look for**

* Unexpected removal of functions from `available_filter_functions` or missing address lists.
* New or obscure `kprobe_events` entries that you did not create.
* Changes in `enabled_functions` or `touched_functions` that do not match expected tracing activity.

**Safe inspection commands**

```bash
# Read the lists (use sudo if required, but prefer offline copies)
cat /sys/kernel/tracing/available_filter_functions
cat /sys/kernel/tracing/enabled_functions
cat /sys/kernel/tracing/kprobe_events
```

**Detection tips**

* Snapshot these files on a known-good host and compare (`diff`) to suspicious hosts.
* Correlate with auditd logs for open/read/write operations against `/sys/kernel/tracing/*`.
* Unexpected absence of common functions (e.g., if your kernel usually lists many functions) can be a sign of tampering.

---

### Kernel Modules

**Paths**

```
/sys/module/*
/proc/modules
/proc/kallsyms
/proc/vmallocinfo
/proc/sys/kernel/tainted
```

**Why check these**
Kernel modules and symbols are the most direct place to observe loaded code in the kernel. Concealment techniques may hide module names from `/proc/modules` or tamper with `kallsyms` to remove symbol names. `vmallocinfo` shows kernel dynamic memory allocations which can reveal strange allocations; `tainted` indicates whether the kernel is in a non-standard/tainted state (third-party modules, proprietary drivers, etc.).

**What to look for**

* Mismatch between `/sys/module/*` directory listing and `/proc/modules`.
* Missing or obfuscated symbols in `/proc/kallsyms`.
* Unexpected entries in `/proc/vmallocinfo` (large anonymous allocations or allocations with suspicious call paths).
* `cat /proc/sys/kernel/tainted` showing taint flags (non-zero) when you expect a clean kernel.

**Safe inspection commands**

```bash
ls -la /sys/module
cat /proc/modules
head -n 50 /proc/kallsyms
cat /proc/vmallocinfo | head
cat /proc/sys/kernel/tainted
```

**Detection tips**

* Compare module lists with external inventory (configuration management / known-good snapshot).
* If modules appear in kernel memory but not in `/sys/module` or `/proc/modules`, that suggests concealment.
* Keep immutable copies of `/proc/kallsyms` and `/proc/modules` for offline analysis.

---

### BPF Maps

**Paths**

```
/sys/fs/bpf/
```

**Why check these**
BPF programs & maps are increasingly used for observability but can also be abused to intercept or filter kernel behavior without a traditional LKM. Hidden or unexpected BPF maps and programs can indicate non-standard in-kernel logic.

**What to look for**

* Unexpected map names, programs pinned under `/sys/fs/bpf`.
* Long-running or recently-created BPF objects that you did not deploy.

**Safe inspection commands**

```bash
ls -la /sys/fs/bpf
bpftool prog show    # requires bpftool, read-only listing
bpftool map show
```

**Detection tips**

* Use `bpftool` to list programs and maps and cross-check against your deployment policy.
* Audit BPF load events where possible; track which UID/comm loaded BPF objects.

---

### Kernel Logs

**Paths**

```
/var/log/dmesg*
/var/log/kern.log
/dev/kmsg
```

**Why check these**
Kernel logs capture module loads, module error messages, driver messages, and may show failed attempts to insert/unload modules or kernel-level warnings. Tampering components sometimes suppress or alter kernel logs; checking multiple log sinks and comparing timestamps helps identify anomalies.

**What to look for**

* Missing expected module load/unload messages around known events.
* Repeated or suppressed errors correlated with module load/unload attempts.
* Changes in timestamp sequences or log gaps.

**Safe inspection commands**

```bash
# Rotate or copy logs for offline analysis
sudo cp /var/log/kern.log /tmp/kern.log.copy
sudo dmesg --ctime | tail -n 200
sudo journalctl -k --no-pager | tail -n 200
```

**Detection tips**

* Correlate kernel logs with other system logs and audit events.
* Look for evidence of suppressed messages (e.g., external packet captures still show activity but local logs show no corresponding kernel events).

---

## Practical detection techniques (safe examples)

### 1) Cross-verify host vs external evidence

* Capture network traffic using a separate, trusted device on the same segment (mirror port/TAP) and compare observed connections to the host’s `/proc/net/*` and `ss` output.
* If you see packets for a listening service but the host reports no socket, that’s a significant indicator.

### 2) Snapshot and diff

* Create periodic snapshots of the above files on known-good systems and suspicious systems; use `diff` to find unexpected changes.

```bash
# Simple snapshot and diff example (safe, read-only)
mkdir -p /tmp/venom-snapshots/good
cat /proc/modules > /tmp/venom-snapshots/good/proc_modules.txt
cat /sys/kernel/tracing/available_filter_functions > /tmp/venom-snapshots/good/trace_funcs.txt
# Later, on suspect host
cat /proc/modules > /tmp/venom-snapshots/suspect/proc_modules.txt
diff -u /tmp/venom-snapshots/good/proc_modules.txt /tmp/venom-snapshots/suspect/proc_modules.txt
```

### 3) Audit & file monitoring

* Use `auditd` or your EDR’s file-watching capability to monitor reads/writes/execs against sensitive tracing and module paths. Example audit rules (illustrative / defensive):

```bash
# Example (read-only listing shown). Add rules in a controlled environment.
# Watch attempts to read/write tracing control files
auditctl -w /sys/kernel/tracing -p rwa -k tracing-watch
# Watch module information access
auditctl -w /proc/modules -p r -k modules-watch
```

> **Note:** Using `auditctl` changes kernel auditing; test in lab environments first and ensure logging is sent to a secure, centralized collector.

### 4) Use specialized tools

* `bpftool` for BPF inspection.
* `lsmod` / `modinfo` / `cat /proc/modules` for module checks.
* `ss -tunap` and `tcpdump` (external capture) for network comparisons.

---

## Indicators of compromise (examples to escalate)

* Discrepancy between `/proc/net/*` (or `ss`) and an external packet capture (packets on wire with no host socket).
* `/proc/modules` missing modules that were previously present or modules present in memory dumps but not listed.
* Removed or truncated entries in `/sys/kernel/tracing/*`, unexpected `kprobe_events`, or nonstandard `enabled_functions`.
* Unexplained `tainted` kernel state without known reason.
* New, pinned objects under `/sys/fs/bpf/` that are unaccounted for.

---

## Forensics & evidence collection (preserve integrity)

* Always collect evidence in a forensically sound manner: avoid running unknown binaries on the suspect host, prefer read-only mounts or live memory capture tools used by your IR playbook.
* Preserve:

  * External packet captures (pcap) from a trusted tap.
  * `/proc/modules`, `/proc/kallsyms`, `ls -la /sys/module` listings.
  * Copies of `/sys/kernel/tracing/*` and `/sys/fs/bpf/*`.
  * Kernel logs (`dmesg`, `journalctl -k`) and audit logs.
* Document timestamps and collection commands for chain-of-custody.

---

