# AP Verify Tool - GitHub 업로드 스크립트
# 실행: .\push.ps1
# 기능: 날짜별 스냅샷 + 릴리즈노트 작성 + GitHub 업로드

$date = Get-Date -Format "yyyyMMdd"
$dateDisplay = Get-Date -Format "yyyy-MM-dd"

Write-Host ""
Write-Host "========================================" -ForegroundColor Cyan
Write-Host "  AP Verify Tool - GitHub Upload" -ForegroundColor Cyan
Write-Host "  Date: $dateDisplay" -ForegroundColor Cyan
Write-Host "========================================" -ForegroundColor Cyan
Write-Host ""

# 1. main_app.py 날짜별 스냅샷 복사
if (Test-Path "main_app.py") {
    Copy-Item "main_app.py" "main_app_$date.py" -Force
    Write-Host "[OK] main_app_$date.py snapshot created" -ForegroundColor Green
} else {
    Write-Host "[WARN] main_app.py not found" -ForegroundColor Yellow
}

# 2. 릴리즈 노트 작성
$releaseDir  = "release_notes"
$releaseFile = "$releaseDir\RELEASE_$date.md"

if (-not (Test-Path $releaseDir)) {
    New-Item -ItemType Directory -Path $releaseDir | Out-Null
}

if (-not (Test-Path $releaseFile)) {
    Write-Host ""
    Write-Host "Release note for $date" -ForegroundColor Yellow
    Write-Host "(Enter empty line to finish)" -ForegroundColor Gray
    Write-Host ""

    $lines = @()
    $lines += "# Release Note - $dateDisplay"
    $lines += ""
    $lines += "## Changes"
    $lines += ""

    Write-Host "Enter changes (one per line, empty line to finish):"
    while ($true) {
        $input_line = Read-Host "  >"
        if ($input_line -eq "") { break }
        $lines += "- $input_line"
    }

    Write-Host ""
    $version = Read-Host "Version tag (e.g. v0.0.2, Enter to skip)"
    if ($version -ne "") {
        $lines += ""
        $lines += "---"
        $lines += "**Version:** $version"
    }

    $lines += ""
    $lines += "**Files:** main_app_$date.py"
    $lines += "**Python:** $(python --version 2>&1)"

    [System.IO.File]::WriteAllText(
        (Resolve-Path $releaseDir).Path + "\RELEASE_$date.md",
        ($lines -join "`n"),
        [System.Text.Encoding]::UTF8
    )
    Write-Host "[OK] release_notes\RELEASE_$date.md created" -ForegroundColor Green
} else {
    Write-Host "[INFO] RELEASE_$date.md already exists, skipping" -ForegroundColor Gray
}

# 3. 커밋 메시지
Write-Host ""
$msg = Read-Host "Commit message"
if ($msg -eq "") {
    $msg = "Update $date"
}

# 4. Git push
Write-Host ""
Write-Host "Running git add / commit / push..." -ForegroundColor Cyan

git add .
git commit -m $msg
git push

Write-Host ""
Write-Host "========================================" -ForegroundColor Green
Write-Host "  GitHub upload complete!" -ForegroundColor Green
Write-Host "  Snapshot : main_app_$date.py" -ForegroundColor Green
Write-Host "  Release  : release_notes\RELEASE_$date.md" -ForegroundColor Green
Write-Host "  Commit   : $msg" -ForegroundColor Green
Write-Host "========================================" -ForegroundColor Green
