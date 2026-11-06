# Lessons

## OSV `published` dates aren't fix dates

Expected: split dev/test on each OSV record's `published` date.
Actual: every 2020 nDPI record says 2020-06-24. That's the day OSV backfilled
old OSS-Fuzz bugs, so a split on it would put three years of fixes on one day.
Next time: date a fix by its git commit date (`git show -s --format=%cI`),
which is what `mine.py` records and `pairs.py` splits on.

## A third of the fixes aren't in library code

Expected: most of the 133 OSS-Fuzz fix commits would change `src/lib/`.
Actual: 29 changed no `.c` file under `src/lib/` (mostly fuzz harnesses and
`example/reader_util.c`), 7 were merge commits, and 2 touched more than 5
files. 95 survived mining, and 89 pairs survived label cleaning.
Next time: budget for losing 30-40% of OSV fix commits before picking a
project, and check the fix paths before committing to a sample size.

## urllib can't verify HTTPS on python.org's macOS Python

Expected: `urllib.request.urlopen` would download the OSV zip.
Actual: `CERTIFICATE_VERIFY_FAILED`. The python.org installer ships without
CA certificates until its "Install Certificates.command" is run.
Next time: download with `curl` in shell scripts. It uses the system trust
store. Don't turn off verification to get around it.

## Joern renames same-named methods across files

Expected: method full names would be unique per file.
Actual: with 238 copies of nDPI files in one CPG, Joern appends
`<duplicate>N` to full names (`init_protocol_defaults<duplicate>1`).
Next time: key methods by (filename, short name), never by full name, when
one CPG holds several versions of the same file.

## "Has no identifiers" isn't the same as "is constant"

Expected: a size argument with no identifiers in its AST is a constant, and
one with identifiers isn't.
Actual: `sizeof(packet->field)` contains identifiers but is fixed at compile
time. 1,305 of 3,434 `risky_copy` findings (38%) were this false alarm. I
found it by reading the findings while writing the walkthrough, after the
first evaluation run.
Next time: dump a sample of each rule's findings and read them before the
first scored run. Decide constness from node types (literal, `sizeOf`,
operators over constants), not from "contains an identifier".
