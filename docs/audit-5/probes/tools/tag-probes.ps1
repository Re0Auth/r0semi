# Put every audit probe behind the `audit5` build tag, so the normal suite
# (go build/vet/test ./...) goes back to green while the probes stay runnable with
# `go test -tags audit5 ./...`.
#
# Why a build tag and not deletion: the probes ARE the evidence for the findings —
# in this project a finding is not a finding until a test can fail on it. Tagging
# keeps all of them, keeps them compiling, and keeps the tree green for everyone
# else. Revert with:  git clean -fd  (probe files are all untracked) or by removing
# the first two lines of each file.
$ErrorActionPreference = 'Stop'
$root = (Get-Location).Path
$tag = 'audit5'
$utf8NoBom = New-Object System.Text.UTF8Encoding($false)

function Get-Files {
    param([string]$Pattern)
    Get-ChildItem -Path $root -Recurse -File -Filter $Pattern |
        Where-Object { $_.FullName -notmatch '\\node_modules\\|\\.git\\' }
}

$targets = @()
foreach ($p in @('*zzprobe*.go', '*zz_probe*.go', '*zzverify*.go')) {
    $targets += Get-Files -Pattern $p
}
# everything under internal/zzprobe/ (the black-box probe packages)
$targets += Get-ChildItem -Path (Join-Path $root 'internal\zzprobe') -Recurse -File -Filter '*.go' -ErrorAction SilentlyContinue
$targets = $targets | Sort-Object FullName -Unique

$tagged = 0
$skipped = 0
foreach ($f in $targets) {
    $text = [System.IO.File]::ReadAllText($f.FullName, [System.Text.Encoding]::UTF8)
    if ($text -match '^\s*(//go:build|// \+build)') { $skipped++; continue }
    $new = "//go:build $tag`n`n" + $text
    [System.IO.File]::WriteAllText($f.FullName, $new, $utf8NoBom)
    $tagged++
}

Write-Output "tagged:   $tagged"
Write-Output "skipped (already had a build constraint): $skipped"

# Every internal/zzprobe/<pkg> directory now has only tagged files, so without the
# tag the package would not exist and `go test ./...` would report
# "build constraints exclude all Go files". An untagged doc.go with the inverse
# constraint keeps the package real in both modes.
$stubs = 0
foreach ($dir in Get-ChildItem -Path (Join-Path $root 'internal\zzprobe') -Directory -Recurse) {
    $goFiles = Get-ChildItem -Path $dir.FullName -File -Filter '*.go'
    if ($goFiles.Count -eq 0) { continue }
    $untagged = @()
    foreach ($g in $goFiles) {
        $t = [System.IO.File]::ReadAllText($g.FullName, [System.Text.Encoding]::UTF8)
        if ($t -notmatch '^\s*(//go:build|// \+build)') { $untagged += $g }
    }
    if ($untagged.Count -gt 0) { continue }
    $pkg = 'zzprobe'
    foreach ($g in $goFiles) {
        $t = [System.IO.File]::ReadAllText($g.FullName, [System.Text.Encoding]::UTF8)
        $m = [regex]::Match($t, '(?m)^package\s+([A-Za-z0-9_]+)')
        if ($m.Success) { $pkg = $m.Groups[1].Value; break }
    }
    $stub = Join-Path $dir.FullName 'doc.go'
    $body = "//go:build !$tag`n`n" +
            "// Package $pkg holds the round-5 audit probes for this area. They are`n" +
            "// behind the ``$tag`` build tag: run them with `go test -tags $tag ./...`.`n" +
            "// Without the tag this package is intentionally empty, so the normal`n" +
            "// `go test ./...` stays green. See docs/security-audit-5.md.`n" +
            "package $pkg`n"
    [System.IO.File]::WriteAllText($stub, $body, $utf8NoBom)
    $stubs++
}
Write-Output "doc.go stubs written: $stubs"
