# llama.SPY Privilege Separation (optional `--serve`)

FreeBSD-first design for an optional metrics microservice. **0.2.0 implements
the socketpair split**: the collector never binds, and the serve child is the
only process that listens. SHM is still not implemented. Capsicum (`cap_enter`)
is used on FreeBSD; Linux uses a seccomp deny-list plus best-effort landlock
on the serve child.

## Invariant

```
[ high-priv collector ] --socketpair / SHM SnoopV1--> [ dropped-priv serve ]
        |                                                    |
   DTrace / mem read                                   HTTP / TUI only
   NEVER binds :443 / :8080                            no dtrace, no ptrace
```

- Collector: attach backends only; push `SnoopV1Frame` over an inherited FD.
- Serve: listen/accept/render only; receive frames; never opens `/dev/dtrace*`.
- CLI: `llamaspy --serve 127.0.0.1:9100 --api-key-file PATH ...` (default
  `127.0.0.1:9100`). Every listener requires `--api-key` or `--api-key-file`.
  Non-loopback addresses, including `0.0.0.0`, are refused even when a key
  is set (LS1). A missing key is refused on loopback too.

## FreeBSD — Capsicum + socketpair (concrete sequence)

1. **Parent** creates `socketpair(AF_UNIX, SOCK_SEQPACKET, 0, sv)` (or
   `SOCK_STREAM` if SEQPACKET unavailable). Optionally `shm_open` a SnoopV1
   ring (**mode 0600**, SnoopV1-only — LS6) for a later SHM path; MVP
   `--serve` should stay socketpair-only (see Race conflict below).
2. **Dual-child fork (LS2):** parent forks **collector child** and **serve
   child**, then remains a **reaper** (`waitpid` / supervise). One fork is
   not enough — do not run collector+serve in a single child. Prefer
   double-fork only if daemonizing *and* a supervisor still reaps peers.
3. **Collector (before Capsicum):**
   - Close the serve-side socket end.
   - Resolve DTrace script path, open `/usr/sbin/dtrace` or libdtrace, attach
     to `--pid` while still fully privileged.
   - Optionally open SHM ring RW.
4. **Collector Capsicum enter:**
   - `cap_rights_limit` on the IPC FD: `CAP_SEND` / `CAP_RECV` only (no
     `CAP_ACCEPT`, no `CAP_BIND`, no filesystem rights).
   - Limit any leftover FDs (script was already read; prefer embedding the
     script text so no directory FD remains).
   - `cap_enter()` — after this, collector cannot open new paths or bind.
5. **Serve (before Capsicum):**
   - Close the collector-side socket end; **FD scrub** — no dtrace/dir FDs
     inherited (LS3).
   - **LS1:** resolve bind address; **hard-reject** non-loopback (not just
     default localhost). Then `bind` + `listen`.
   - `setgid` / `setuid` to an unprivileged user (e.g. `nobody` or a dedicated
     `llamaspy` account) **before** `cap_enter`.
6. **Serve Capsicum enter:**
   - Rights on listen FD: `CAP_ACCEPT`, `CAP_READ`, `CAP_WRITE`, `CAP_EVENT`.
   - Rights on IPC FD: `CAP_RECV` (and `CAP_SEND` only if ACKs are required).
   - No `CAP_LOOKUP` / directory FDs; no raw sockets beyond the listen FD.
   - `cap_enter()`.
7. **Runtime:** collector writes **`snoop_hton`** frames on the socket
   (privilege boundary); serve reads, admits frames (LS5: magic/version/size),
   and exposes `/metrics` or feeds the TUI. Crash of serve must not leave
   collector listening on the net (it never did). **LS4 peer-death:** if
   either child exits, the other must exit (parent reaper or socket EOF) so
   DTrace does not orphan.

### Capsicum notes

- Prefer limiting rights **then** `cap_enter`, never the reverse.
- `SOCK_SEQPACKET` preserves frame boundaries for 64-byte `SnoopV1Frame`.
- Frames on the socket use **`snoop_hton`** at the privilege boundary; SHM
  (when used) stays **host byte order** (see DESIGN.md).

### SHM vs read-only serve (Race Review — conflict call-out)

Earlier draft said "map read-only in serve". That **conflicts with SPSC**: the
consumer **must write `tail`**. Options before coding SHM into `--serve`:

| Option | Serve map | Notes |
|--------|-----------|-------|
| **A. socketpair-only (MVP recommend)** | N/A | Collector sends `snoop_hton` frames; no SHM. `--serve` stub stays on this path until SHM protocol lands. |
| B. Dual mapping | RO data + RW `tail` page (or separate RW control mapping) | Capsicum rights per FD; more moving parts. |
| C. Seqlock / double-buffer | Truly RO serve | Single-writer snapshot; serve never writes; no classic SPSC `tail`. |

**Recommendation:** keep MVP `--serve` on **socketpair only**. Do not ship a
RO SHM map that pretends to be SPSC.

### Boundary hard rules (P0) — cite `/workspace/reviews/llama-spy-boundary-review.md`

Keep `--serve` stubbed until these are implemented. Documented now so the fork
path cannot ship without them:

1. **LS1 — Loopback-only bind:** hard-reject any non-loopback bind for
   `--serve` (not merely "default localhost"). Refuse `0.0.0.0`, `*`, LAN
   addrs, etc. at argv parse / before `bind`.
2. **LS2 — Dual-child fork topology:** one `fork` is **not** collector+serve.
   Required shape: parent creates `socketpair` (+ optional shm), forks
   **collector child** and **serve child**, then parent acts as **reaper**
   (waitpid / supervise). Do not collapse into a single child that does both.
3. **LS3 — FD scrub / CLOEXEC:** scrub inherited FDs before each child
   runs its job. `FD_CLOEXEC` on everything that should not cross `exec`.
   **Never** inherit dtrace, directory, or script FDs into serve. **No
   `SCM_RIGHTS`** after privilege drop / `cap_enter`.
4. **LS4 — Peer-death:** if serve dies, collector must exit (and vice
   versa) so DTrace / attach does not orphan. Parent reaper or
   `POLLHUP`/`EOF` on the socketpair end is enough for MVP; document the
   chosen signal.

**P1 (brief):** LS5 frame admit gate (magic/version/size before trust);
LS6 SHM mode `0600` + SnoopV1-only contents — note LS6 also tensions with
any "RO map" story (see Race conflict above). Full board:
`/workspace/reviews/llama-spy-boundary-review.md`.

## Linux sketch — landlock + seccomp (peer, not v1 center)

Linux is a peer after FreeBSD. Same fork/`socketpair` topology; different
sandbox primitives:

1. `socketpair` + fork as above.
2. **Collector:** attach (eBPF / `process_vm_readv` / HTTP poll as configured),
   then:
   - Landlock: allow only the paths already needed (often none if script was
     read into memory); deny bind/listen net via not holding those sockets.
   - seccomp-bpf filter: allow `read`/`write`/`sendmsg`/`recvmsg`/`futex`/
     `exit_group`/`clock_gettime`/…; deny `bind`, `listen`, `accept`,
     `ptrace` (after attach), `openat` (after path stage).
3. **Serve:** bind/listen first, drop to `nobody`, then Landlock with no FS
   access + seccomp allowing accept/read/write/epoll on the listen + IPC FDs
   only.
4. Optional: `PR_SET_NO_NEW_PRIVS` before seccomp.

Yama/`kernel.yama.ptrace_scope` may already block late ptrace — treat that as
orthogonal to landlock.

## What 0.2.0 still skips

- SHM ring publish/consume (header + DESIGN sketch only; `--serve` is socketpair).
- TLS termination in-process. Put a reverse proxy in front if you need TLS.
- FreeBSD `cap_enter` is compiled in but was not executed on a FreeBSD host
  in the 0.2.0 bring-up (Linux tests covered the socketpair, the API key, and
  the loopback refusal).
- The Linux sandbox is a syscall deny-list (collector: no bind/listen/accept;
  serve: no connect/exec/ptrace/process_vm_*) plus landlock with no filesystem
  rules. It is not a full allow-list seccomp policy.

Keep the FreeBSD Capsicum path compiling behind
`#ifdef __FreeBSD__` and ship the Linux landlock/seccomp path as a peer
`#ifdef __linux__` — do not invert the FreeBSD-first priority.
