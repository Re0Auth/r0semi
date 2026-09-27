# Reproducibility experiment for A-FE-9 (verifier probe; read-only w.r.t. tracked tree).
# Builds the frontend twice and snapshots per-file sha256 of internal/webui/dist after each build.
$ErrorActionPreference = 'Continue'
$root = '.'
$dist = Join-Path $root 'internal\webui\dist'
$out  = Join-Path $root 'scratchpad\audit\probes\verify-web'

function Snapshot([string]$name) {
  $prefix = $dist + '\'
  Get-ChildItem -Recurse -File $dist | ForEach-Object {
    $rel = $_.FullName.Substring($prefix.Length)
    $h = (Get-FileHash -Algorithm SHA256 -LiteralPath $_.FullName).Hash
    "{0}`t{1}`t{2}" -f $rel, $h, $_.Length
  } | Sort-Object | Set-Content -Encoding UTF8 (Join-Path $out "$name.tsv")
  "snapshot $name : " + (Get-ChildItem -Recurse -File $dist | Measure-Object).Count + " files"
}

Snapshot 'dist-run0'

foreach ($n in 1, 2) {
  Push-Location (Join-Path $root 'web')
  "=== build $n start $(Get-Date -Format o) ==="
  & pnpm run build 2>&1 | Select-Object -Last 25
  "=== build $n exit=$LASTEXITCODE $(Get-Date -Format o) ==="
  Pop-Location
  Snapshot "dist-run$n"
}

# version.json after each build is captured by the snapshot; print the last two.
"--- version.json run1/run2 ---"
Get-Content (Join-Path $dist '_app\version.json') -ErrorAction SilentlyContinue
