#!/usr/bin/env bash
# End-to-end: OSV labels -> mined files -> Joern CPG -> pairs -> precision report.
# Needs git, curl, python3 (3.10+) and joern / joern-parse on PATH. No paid APIs.
set -euo pipefail
cd "$(dirname "$0")"

REPO_URL="https://github.com/ntop/nDPI.git"

mkdir -p data out

if [ ! -d data/nDPI/.git ]; then
  echo "== cloning nDPI (blobless; file contents are fetched on demand)"
  git clone --quiet --filter=blob:none "$REPO_URL" data/nDPI
fi

echo "== OSV fix commits"
# curl uses the system trust store. python.org builds on macOS have no CA
# certificates until "Install Certificates.command" is run, so urllib fails.
curl -fsSL -o data/osv-oss-fuzz.zip "https://osv-vulnerabilities.storage.googleapis.com/OSS-Fuzz/all.zip"
python3 -m cpg_eval.osv --package ndpi --zip data/osv-oss-fuzz.zip --out data/fixes.jsonl

echo "== mining before/after files"
rm -rf data/files
python3 -m cpg_eval.mine

echo "== building the CPG"
joern-parse data/files -o out/cpg.bin --language c > out/joern-parse.log 2>&1

echo "== extracting methods and findings"
# importCpg makes a new workspace project each run (cpg.bin, cpg.bin1, ...),
# each a full copy of the graph. Start clean so they don't pile up.
rm -rf workspace
joern --script joern/extract.sc --param cpgFile=out/cpg.bin --param outDir=out 2>&1 | grep -v WARN

echo "== pairs and split"
python3 -m cpg_eval.pairs

echo "== evaluation"
python3 -m cpg_eval.evaluate
