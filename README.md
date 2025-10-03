<div align="center">
  <img src="https://i.postimg.cc/wBzfJZYW/venom.png" alt="banner" style="max-width:100%; border-radius:12px;"/> 
</div>

<h1 align="center">Venom</h1>

<div align="center">
  <strong>Simple, but powerful</strong><br>
  A <b><i>Linux Kernel Module</i></b> 
</div>

--- 

> [!Important]
> Venom — educational only. This repository explains concepts and historic categories of kernel/userland malware so defenders can recognize, study, and detect them. Use only in legal, controlled environments (isolated VMs, CTF labs you own, or instructor-approved training).


## 

## Syscalls / Kernel hooks monitored by Venom

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

# Quick guidance for readers (defensive)
- This table documents *which kernel touchpoints* Venom monitors and *why* — not how to implement hooks.  
- If you are a defender: audit for the indicators in the rightmost column (e.g., mismatched `/proc` output, failed module loads, anomalies in read/write behavior, and differences between passive packet captures and `/proc/net`).  
- If you are a researcher: use isolated, instrumented environments (air-gapped VMs, offline snapshots) and follow responsible disclosure and legal guidelines before experimenting.


