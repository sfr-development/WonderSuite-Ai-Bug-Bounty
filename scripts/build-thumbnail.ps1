# YouTube thumbnail builder for the "WonderSuite in Antigravity" demo video.
# Output: docs/youtube_thumbnail.png  (1280x720, target <300 KB)
#
# Composition:
#   - Dark navy gradient background + subtle grid + orange radial glow
#   - Top-left: Antigravity logo with "IN ANTIGRAVITY" caption
#   - Top-right: Burp Suite logo with red diagonal strike-through
#   - Center: large WonderSuite logo with glow
#   - Bottom: massive "BURP IS DEAD" tagline + sub-line
#
# Tooling: pure System.Drawing.Common — no external deps beyond stock Windows.

Add-Type -AssemblyName System.Drawing
Add-Type -AssemblyName System.Drawing.Drawing2D 2>$null  # may be implicit

$ErrorActionPreference = 'Stop'

$repo  = 'C:\Users\sfrde\wondersuite-release'
$assets = "$repo\docs\thumbnail_assets"
$outDir = "$repo\docs"
$out = "$outDir\youtube_thumbnail.png"

$W = 1280
$H = 720

$bmp = New-Object System.Drawing.Bitmap $W, $H
$g = [System.Drawing.Graphics]::FromImage($bmp)
$g.SmoothingMode      = [System.Drawing.Drawing2D.SmoothingMode]::AntiAlias
$g.InterpolationMode  = [System.Drawing.Drawing2D.InterpolationMode]::HighQualityBicubic
$g.PixelOffsetMode    = [System.Drawing.Drawing2D.PixelOffsetMode]::HighQuality
$g.TextRenderingHint  = [System.Drawing.Text.TextRenderingHint]::ClearTypeGridFit
$g.CompositingQuality = [System.Drawing.Drawing2D.CompositingQuality]::HighQuality

# ── 1. Background — dark navy diagonal gradient ───────────────────────────
$bgRect = New-Object System.Drawing.Rectangle 0, 0, $W, $H
$bgBrush = New-Object System.Drawing.Drawing2D.LinearGradientBrush(
    $bgRect,
    ([System.Drawing.Color]::FromArgb(255, 8, 11, 22)),    # deep navy
    ([System.Drawing.Color]::FromArgb(255, 28, 18, 8)),    # warm dark for orange undertone
    [System.Drawing.Drawing2D.LinearGradientMode]::ForwardDiagonal
)
$g.FillRectangle($bgBrush, $bgRect)
$bgBrush.Dispose()

# ── 2. Subtle grid pattern (tech vibe) ─────────────────────────────────────
$gridPen = New-Object System.Drawing.Pen ([System.Drawing.Color]::FromArgb(28, 80, 100, 130)), 1
for ($x = 0; $x -le $W; $x += 40) { $g.DrawLine($gridPen, $x, 0, $x, $H) }
for ($y = 0; $y -le $H; $y += 40) { $g.DrawLine($gridPen, 0, $y, $W, $y) }
$gridPen.Dispose()

# ── 3. Orange radial glow behind the center logo ───────────────────────────
# PathGradientBrush — concentric falloff from accent color to transparent.
$glowPath = New-Object System.Drawing.Drawing2D.GraphicsPath
$glowRect = New-Object System.Drawing.Rectangle ([int]($W/2 - 520)), ([int]($H/2 - 380)), 1040, 760
$glowPath.AddEllipse($glowRect)
$glowBrush = New-Object System.Drawing.Drawing2D.PathGradientBrush $glowPath
$glowBrush.CenterPoint = New-Object System.Drawing.PointF (($W/2), ($H/2 - 30))
$glowBrush.CenterColor = [System.Drawing.Color]::FromArgb(170, 232, 161, 69)   # WS orange
$glowBrush.SurroundColors = @([System.Drawing.Color]::FromArgb(0, 0, 0, 0))
$g.FillPath($glowBrush, $glowPath)
$glowBrush.Dispose(); $glowPath.Dispose()

# Helper: paste an image preserving aspect, target height.
function Paste-Image($graphics, $path, $x, $y, $targetH) {
    $img = [System.Drawing.Image]::FromFile($path)
    $ratio = $img.Width / $img.Height
    $w = [int]($targetH * $ratio)
    $h = [int]$targetH
    $graphics.DrawImage($img, $x, $y, $w, $h)
    $img.Dispose()
    return @{ Width = $w; Height = $h }
}

# ── 4. Top-left: Antigravity badge ─────────────────────────────────────────
$agSize = Paste-Image $g "$assets\antigravity.png" 40 38 56
# Caption "IN ANTIGRAVITY" right of the logo
$capFont = New-Object System.Drawing.Font 'Segoe UI', 16, ([System.Drawing.FontStyle]::Bold)
$capBrush = New-Object System.Drawing.SolidBrush ([System.Drawing.Color]::FromArgb(255, 220, 230, 240))
$g.DrawString('IN ANTIGRAVITY', $capFont, $capBrush, ($agSize.Width + 55), 56)
$subFont = New-Object System.Drawing.Font 'Segoe UI', 11, ([System.Drawing.FontStyle]::Regular)
$subBrush = New-Object System.Drawing.SolidBrush ([System.Drawing.Color]::FromArgb(180, 150, 170, 190))
$g.DrawString('Google''s AI-first IDE', $subFont, $subBrush, ($agSize.Width + 55), 80)

# ── 5. Top-right: Burp Suite — crossed out ─────────────────────────────────
$burpImg = [System.Drawing.Image]::FromFile("$assets\burp.png")
$burpRatio = $burpImg.Width / $burpImg.Height
$burpH = 56
$burpW = [int]($burpH * $burpRatio)
$burpX = $W - $burpW - 50
$burpY = 42
$g.DrawImage($burpImg, $burpX, $burpY, $burpW, $burpH)
$burpImg.Dispose()
# Red diagonal strike through the Burp logo
$strikePen = New-Object System.Drawing.Pen ([System.Drawing.Color]::FromArgb(230, 239, 68, 68)), 6
$strikePen.LineJoin = 'Round'
$g.DrawLine($strikePen, ($burpX - 8), ($burpY + $burpH + 6), ($burpX + $burpW + 8), ($burpY - 6))
$strikePen.Dispose()
# "REPLACED" stamp under the burp logo
$replacedFont = New-Object System.Drawing.Font 'Impact', 18, ([System.Drawing.FontStyle]::Regular)
$replacedBrush = New-Object System.Drawing.SolidBrush ([System.Drawing.Color]::FromArgb(255, 239, 68, 68))
$g.DrawString('REPLACED', $replacedFont, $replacedBrush, ($burpX + 6), ($burpY + $burpH + 12))

# ── 6. Center: WonderSuite logo (big) ──────────────────────────────────────
$wsImg = [System.Drawing.Image]::FromFile("$assets\wondersuite.png")
$wsRatio = $wsImg.Width / $wsImg.Height
$wsTargetW = 760
$wsTargetH = [int]($wsTargetW / $wsRatio)
$wsX = [int]($W/2 - $wsTargetW/2)
$wsY = 150
# Drop-shadow first
$shadow = New-Object System.Drawing.Imaging.ColorMatrix
$shadow.Matrix33 = 0.55
$ia = New-Object System.Drawing.Imaging.ImageAttributes
$ia.SetColorMatrix($shadow)
$shadowRect = New-Object System.Drawing.Rectangle ($wsX + 6), ($wsY + 8), $wsTargetW, $wsTargetH
$g.DrawImage($wsImg, $shadowRect, 0, 0, $wsImg.Width, $wsImg.Height,
    [System.Drawing.GraphicsUnit]::Pixel, $ia)
$ia.Dispose()
# Real logo
$g.DrawImage($wsImg, $wsX, $wsY, $wsTargetW, $wsTargetH)
$wsImg.Dispose()

# ── 7. Bottom: massive tagline "BURP IS DEAD" ──────────────────────────────
# Two-line stack, left line WHITE, accent word ORANGE for clickbait punch.
$titleFont = New-Object System.Drawing.Font 'Impact', 96, ([System.Drawing.FontStyle]::Regular)
$titleBrush = New-Object System.Drawing.SolidBrush ([System.Drawing.Color]::FromArgb(255, 255, 255, 255))
$accentBrush = New-Object System.Drawing.SolidBrush ([System.Drawing.Color]::FromArgb(255, 255, 185, 103))

# Measure "BURP IS DEAD" centered.
$line = 'BURP IS DEAD.'
$titleSize = $g.MeasureString($line, $titleFont)
$titleX = ($W - $titleSize.Width) / 2
$titleY = $H - 180

# Heavy shadow first (offset 5,5 with blur emulation via 3 stacked draws)
$shadowBrush = New-Object System.Drawing.SolidBrush ([System.Drawing.Color]::FromArgb(160, 0, 0, 0))
foreach ($off in @(@(7,7), @(5,5), @(3,3))) {
    $g.DrawString($line, $titleFont, $shadowBrush, ($titleX + $off[0]), ($titleY + $off[1]))
}
$shadowBrush.Dispose()
# Real text: split between white "BURP IS" and orange "DEAD."
$prefix = 'BURP IS '
$suffix = 'DEAD.'
$prefSize = $g.MeasureString($prefix, $titleFont)
$g.DrawString($prefix, $titleFont, $titleBrush, $titleX, $titleY)
$g.DrawString($suffix, $titleFont, $accentBrush, ($titleX + $prefSize.Width - 8), $titleY)

# Sub-line below: "AI runs the pentest in Antigravity"
$subTitleFont = New-Object System.Drawing.Font 'Segoe UI', 22, ([System.Drawing.FontStyle]::Bold)
$subTitleBrush = New-Object System.Drawing.SolidBrush ([System.Drawing.Color]::FromArgb(255, 200, 215, 235))
$subTitle = 'AI runs the whole pentest now — 91 MCP tools, free, native to Antigravity'
$subSize = $g.MeasureString($subTitle, $subTitleFont)
$subX = ($W - $subSize.Width) / 2
$subY = $H - 60
# small shadow
$subShadow = New-Object System.Drawing.SolidBrush ([System.Drawing.Color]::FromArgb(180, 0, 0, 0))
$g.DrawString($subTitle, $subTitleFont, $subShadow, ($subX + 2), ($subY + 2))
$subShadow.Dispose()
$g.DrawString($subTitle, $subTitleFont, $subTitleBrush, $subX, $subY)

# ── 8. Decorative corner accent — thin orange L-shape top-left + bottom-right
$accentPen = New-Object System.Drawing.Pen ([System.Drawing.Color]::FromArgb(255, 232, 161, 69)), 4
$g.DrawLine($accentPen, 24, 24, 24, 100)
$g.DrawLine($accentPen, 24, 24, 100, 24)
$g.DrawLine($accentPen, ($W - 24), ($H - 24), ($W - 24), ($H - 100))
$g.DrawLine($accentPen, ($W - 24), ($H - 24), ($W - 100), ($H - 24))
$accentPen.Dispose()

# ── 9. Save ────────────────────────────────────────────────────────────────
$bmp.Save($out, [System.Drawing.Imaging.ImageFormat]::Png)
$g.Dispose(); $bmp.Dispose()
$capFont.Dispose(); $subFont.Dispose(); $titleFont.Dispose(); $subTitleFont.Dispose()
$replacedFont.Dispose()
$capBrush.Dispose(); $subBrush.Dispose(); $titleBrush.Dispose(); $accentBrush.Dispose()
$replacedBrush.Dispose(); $subTitleBrush.Dispose()

Write-Host "Thumbnail saved: $out  ($([math]::Round((Get-Item $out).Length/1KB,1)) KB)"
