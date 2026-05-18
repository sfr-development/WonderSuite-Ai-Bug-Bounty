# Backfill GitHub release bodies with the actual CHANGELOG.md sections.
# Run once after any historical release that was published with the workflow's
# boilerplate releaseBody. Idempotent — runs gh release edit which overwrites.
#
# Extracts the body between `## [version]` and the next `## [` header, then
# pushes it to the matching GitHub release via gh CLI.

$ErrorActionPreference = 'Stop'
$repo = 'sfr-development/WonderSuite-Ai-Bug-Bounty'
$changelog = Get-Content "$PSScriptRoot\..\CHANGELOG.md" -Raw

# Match each "## [version] — date" header, capture the body until the next "## [" or EOF.
$re = [regex]'(?ms)^\#\#\s*\[(?<ver>[^\]]+)\][^\n]*\n(?<body>.*?)(?=^\#\#\s*\[|\z)'
$matches_ = $re.Matches($changelog)

foreach ($m in $matches_) {
    $ver = $m.Groups['ver'].Value.Trim()
    if ($ver -eq 'Unreleased') { continue }
    $body = $m.Groups['body'].Value.Trim()
    if ([string]::IsNullOrWhiteSpace($body)) { continue }
    $tag = "v$ver"

    # Check if the GitHub release exists.
    $exists = $true
    try { gh release view $tag --repo $repo 1>$null 2>$null } catch { $exists = $false }
    if (-not $exists -or $LASTEXITCODE -ne 0) {
        Write-Host "  $tag — no GitHub release, skipping"
        continue
    }

    # Write body to a temp file (avoids shell-escaping nightmare with markdown
    # backticks, dashes, etc.) and pass via --notes-file.
    $tmp = [System.IO.Path]::GetTempFileName()
    Set-Content -Path $tmp -Value $body -Encoding utf8

    Write-Host "  $tag — updating release notes ($($body.Length) chars)…"
    gh release edit $tag --repo $repo --notes-file $tmp 2>&1 | Out-Null
    Remove-Item $tmp -Force
    if ($LASTEXITCODE -eq 0) {
        Write-Host "    ✓ done"
    } else {
        Write-Host "    ✗ FAILED"
    }
}

Write-Host ""
Write-Host "Backfill complete."
