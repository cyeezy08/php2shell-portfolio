# PHP2Shell (CVE-2026-109618/109619) - Lab Validation & Analytics Report

**Date:** 2026-10-23 · **Environment:** Kali Linux, Docker 28.5.2, isolated loopback lab
**Target:** Official `php:8.4.26-apache` Docker image (Debian 13/trixie, Apache 2.4.69, mod_php prefork) - **vanilla binary, no source patching**
**Exploit:** EDB-ID 52704 (OffSec adjustment of 9bie's chain) + per-build symbol offsets
**Authorization:** Local lab only

## 1. Verdict

**WORKING PRE-AUTH RCE CONFIRMED** against unmodified PHP 8.4.26 (mod_php).

```
PROOF: uid=33(www-data) gid=33(www-data) groups=33(www-data)
```

- Arbitrary command execution as the web worker account, no credentials, no app bug, plain HTTP.
- Full chain completed in **~6.4 s / 5 HTTP POSTs / 1,619 packets** on the successful run.
- **Control:** identical attack against patched `php:8.4.27-apache` fails at stage 1 (heap leak), 3/3 attempts, no proof file. Patch verified effective.

## 2. Exploit chain (as validated)

| Stage | Action | Result |
|---|---|---|
| 0 | Worker rotation over HTTP (target single-worker prefork) | ✓ |
| 1 | `PHP_SESSION_UPLOAD_PROGRESS` OOM → stale-id OOB read → **Zend MM chunk base** via Set-Cookie leak | ✓ (1 attempt) |
| 2 | Second leak → **libphp.so base** (ZVAL_PTR_DTOR) | ✓ (1 attempt, *only with correct offsets*) |
| 3 | Fake reference + forged Zend structures → `pDestructor = zif_system` → `system("id>/out/p1")` | ✓ (1 attempt clean; 5 attempts on first try) |

### Critical operational finding: per-build offsets
EDB 52704 ships hardcoded offsets for the **Debian 12 (bookworm)** build of `php:8.4.26-apache`
(`zif_system=0x43a870, zval_ptr_dtor=0x613c50`). Our pulled tag is the **Debian 13 (trixie)** rebuild of the
same version tag - real offsets `zif_system=0x465370, zval_ptr_dtor=0x65eb60`. With bookworm constants,
stage 2 fails 3/3 ("libphp leak missed"). **Same version number ≠ same binary layout.**
Fix: `docker/offsets.py` extracts symbols from the actual target's `libphp.so` ELF symtab → pass via
`--offsets-file`. This exactly matches Wiz's warning that exploits need per-deployment adaptation, and
explains most "the public PoC doesn't work" reports.

## 3. Traffic analytics (pcap: /tmp/opencode/php2shell-final.pcap)

- 5 POSTs to `/index.php`, all `multipart/form-data`:
  - Small (192 B, boundary `BNDRY12345`) - worker-rotation/session-seed probes
  - Large (83–94 KB, boundary `BBBBBBBBBB`) - OOM/leak stages
- Decoded body fields: `PHPSESSIONID=attacksessionid0001`, `PHP_SESSION_UPLOAD_PROGRESS=pwn`,
  plus mass numeric field names (`1000`, `a0000[0]`) for input-var/memory pressure.
- No User-Agent, no referer, HTTP/1.1, sequential (not concurrent beyond rotation).

## 4. Server-side (blue-team) signals observed

Every failed/partial attempt leaves **loud process-level evidence** in container logs:

```
zend_mm_heap corrupted                      ← allocator integrity check fires
qemu: uncaught target signal 11 (Segfault)  ← UAF dereference
qemu: uncaught target signal 6 (Aborted)    ← zend_mm abort
```

- Apache worker children crash repeatedly during exploitation (core dumps).
- `zend_mm_heap corrupted` + apache2/`php` SIGSEGV within a request window = high-fidelity compromise indicator.
- Successful run still crashed workers during rotation - exploitation is *not* stealthy at the host layer.

## 5. Detection rules (validated against captured traffic)

ikow/php2shell-poc Suricata set (`detection/php2shell.rules`, SID 2026100+) matches our pcap:
- **SID 2026100** - `PHP_SESSION_UPLOAD_PROGRESS` inside multipart POST body → fired on frames 553/1154.
- Recommended additions from observed traffic: boundary `BBBBBBBBBB`/`BNDRY12345`, field name
  `PHPSESSIONID` co-occurring with `PHP_SESSION_UPLOAD_PROGRESS`, POST bodies >80 KB to PHP endpoints
  with numeric-only field names.
- Host-side: alert on `zend_mm_heap corrupted` in php/apache logs; apache2 child SIGSEGV bursts.

## 6. Reliability matrix (our runs)

| Run | Config | Offsets | Result |
|---|---|---|---|
| 1 | tuned lab (8M limit, disp_errors on, 1 worker) | bookworm (wrong) | stage 2 ✗ 3/3 |
| 2 | tuned lab | extracted (correct) | full chain; stage 3 blind-fired, proof written (5 attempts) |
| 3 | tuned lab | extracted | **clean RCE, 1 attempt/stage, 6.4 s** |
| 4 | patched 8.4.27 | extracted | stage 1 ✗ 3/3 - **patch blocks** |

## 7. Reality-check vs. public narrative

- The bug class is real and this public exploit genuinely works - but only after per-build offset
  recovery and (for this variant) a tuned php.ini (`memory_limit=8M`, `display_errors=On`,
  single-worker prefork). The 9bie repo's "pure" variant claims stock-config operation but its leak
  window failed 3/3 on our trixie build - same calibration problem.
- Confirms: (a) fake/AI-slop PoCs are noise, (b) real public exploits are build-fragile,
  (c) in-the-wild actors (Amazon MadPot telemetry since Oct 17) are running adapted chains.

## 8. Artifacts

- `~/php2shell-kit/52704.py` - exploit (EDB 52704)
- `~/php2shell-kit/php2shell-bypass-aslr-exp/` - 9bie lab + `docker/offsets.py` + `out/offsets.env`
- `~/php2shell-kit/php2shell-poc/detection/` - Suricata/Sigma/ModSec rules
- `/tmp/opencode/php2shell-final.pcap`, `/tmp/opencode/php2shell-tuned.pcap` - captures
- Lab: `docker compose` in `php2shell-bypass-aslr-exp/docker/` (port 8088 = vulnerable, 8089 = patched)
