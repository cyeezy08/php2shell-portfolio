# PHP2Shell one week later: why the public exploit fails, and the one line that fixes it

**Target:** CVE-2026-109618 / CVE-2026-109619 (PHP2Shell)
**Tested:** PHP 8.4.26 and 8.4.27, official Docker images, current builds
**Author:** leviathanx (cyeezy08)
**Date:** 2026-10-23

## TL;DR

The public Exploit-DB entry for PHP2Shell (EDB-ID 52704) works. Against a
vanilla PHP 8.4.26 container it gives unauthenticated RCE as www-data in about
six seconds. Most people who ran it saw it fail, and concluded the public
exploits are fake. They are half right: most of the GitHub PoCs are AI
generated noise, but the real one fails for a boring reason. The exploit ships
symbol offsets calibrated on the Debian 12 build of php:8.4.26-apache, and
Docker now serves a Debian 13 rebuild under the same tag. Same version number,
different binary, different offsets. Point the exploit at the offsets of the
binary you are actually attacking and it works.

## The failure everyone hit

EDB 52704 carries two offsets for the libphp.so of the target build:

    zif_system     = 0x43a870
    zval_ptr_dtor  = 0x613c50

Those are the Debian 12 (bookworm) values. The un-suffixed php:8.4.26-apache
tag on Docker Hub now resolves to the Debian 13 (trixie) rebuild
(apache2 2.4.69-1~deb13u1). Pull the tag today and you get a libphp.so whose
real offsets are:

    zif_system     = 0x465370
    zval_ptr_dtor  = 0x65eb60

The exploit has an auto-offsets helper that reads the symbols out of the
running container. It only runs when the offsets file does not exist yet, and
it looks for the helper script relative to the exploit file. Run the exploit
standalone, the way the EDB download lays it out, and the helper is not there.
The script falls back to the bookworm constants without a warning, prints them
as if they were correct, and stage 2 writes to addresses that are tens of
megabytes away from the real functions. Stage 1 still works, stage 2 misses,
and the run ends with EXPLOIT_FAILED. That matches exactly what most people
reported.

## The fix

Read the real offsets from the container's libphp.so ELF symbol table and pass
them in:

    python3 docker/offsets.py <container>          # writes ZIF_OFFSET / DTOR_OFFSET
    python3 52704.py -u http://127.0.0.1:8088/index.php \
      -c 'id>/out/p1' --proof-file out/p1 --offsets-file offsets.env

With correct offsets, against an unmodified php:8.4.26-apache container
(Debian 13 build, Apache 2.4.69, mod_php prefork, tuned php.ini: memory_limit
8M, display_errors On, single worker prefork):

    [*] stage 1: heap leak      -> chunk base = 0x7fff09800000
    [*] stage 2: libphp leak    -> libphp base = 0x7fff0accc000
    [*] stage 3: pDestructor = zif_system
    PROOF: uid=33(www-data) gid=33(www-data) groups=33(www-data)

Full chain: 5 HTTP POSTs, about 6.4 seconds, stage 3 landed first attempt. The
command runs as www-data. No application bug required, no file write, plain
HTTP.

## Reproducibility caveat, stated plainly

That validation ran under qemu-emulated x86 (ARM64 host). On native x86 the
same image, same config, same offsets fails at stage 1: the worker aborts on
the primer request before the stale session state the leak consumes is in
place. The stage 1 leak is timing sensitive and the calibration constants are
tuned to a specific execution profile. The offsets finding is not timing
dependent (symbol table facts, and stage 2 with bookworm constants fails
deterministically on trixie), but anyone reproducing the full chain should
expect to tune the primer timing for their environment. We did not get the
native run working, and we are not claiming we did.

## What the patch does

Same barrage against 8.4.27, 8.3.36 and 8.5.12: stage 1 never lands, zero
corruption traces in the worker logs, no proof. The vulnerable build under the
same barrage shows 13 zend_mm corruption and abort events. The patch holds at
the front door for the calibrated triggers.

Reading the patch (commit 3584a98): the OOM path no longer longjmps out of
request handling. Allocations past memory_limit now succeed up to a hard limit
of two times memory_limit (percent 200) with a delayed error thrown at the next
VM safe point, and past that the worker calls _exit(137). The delayed error
handler still calls zend_bailout() when there is no userland frame, which the
patch argues is safe because the state is valid at VM safe points. We did not
find a hole in that argument in the time we spent on it. The two times window
is by design, not a regression worth reporting.

## On the fake PoC ecosystem

Within 48 hours of disclosure there were thousands of PHP2Shell PoCs on GitHub.
The ones with the most stars patch PHP itself in their lab containers to
introduce the bug they claim to exploit, or require an existing LFI in the
application, or misdescribe both CVEs entirely (one popular repo attributes a
var_destroy unserialize UAF to CVE-2026-109619, which is actually the stale
global state bug). The 2004 pattern repeated: real exploit held back, fakes
circulating, some of the fakes backdoor the person running them. JFrog
documented prank malware in the mix.

The useful takeaway is that "the public exploits do not work" was the wrong
conclusion. One of them works. It was shipped broken, and the break was a
distribution problem, not a research problem.

## Detection

From a captured successful chain (pcap available on request):

- Multipart POSTs to PHP endpoints containing PHP_SESSION_UPLOAD_PROGRESS
  together with an attacker chosen PHPSESSID field, followed by mass numeric
  field names (Suricata SID 2026100 covers this)
- Host side: zend_mm_heap corrupted in PHP or Apache logs, apache2 child
  SIGSEGV/SIGABRT bursts. Every attempt we ran, including the successful one,
  left these traces. Exploitation is loud at the host layer.

## Files

Exploit: EDB-ID 52704 (credit 9bie, OffSec adjustment). Offsets and validation
details: private research repo. Capture of a successful chain available for
detection tuning.
