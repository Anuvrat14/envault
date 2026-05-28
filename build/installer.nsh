; Kill all Dotward processes before install - Pop clears the NSIS stack
!macro customInit
  nsExec::ExecToLog 'taskkill /F /IM "Dotward.exe" /T'
  Pop $0
  nsExec::ExecToLog 'taskkill /F /IM "dotward-server.exe" /T'
  Pop $0
  Sleep 3000
!macroend

!macro customUnInstall
  nsExec::ExecToLog 'taskkill /F /IM "Dotward.exe" /T'
  Pop $0
  nsExec::ExecToLog 'taskkill /F /IM "dotward-server.exe" /T'
  Pop $0
  Sleep 3000
!macroend

; Register Dotward MCP server with Claude Code after install
!macro customInstall
  StrCpy $0 "$LOCALAPPDATA\Programs\dotward\resources\dotward-server.exe"

  ; Try claude CLI first (user may have Claude Code installed)
  nsExec::ExecToLog 'cmd /C claude mcp add dotward -s user "$0" mcp'
  Pop $1

  ; Fallback: write directly to ~/.claude/settings.json (works even if claude not in PATH)
  nsExec::ExecToLog 'powershell -NoProfile -NonInteractive -WindowStyle Hidden -Command \
    "$cfg = Join-Path $env:USERPROFILE \".claude\settings.json\"; \
    $dir = Split-Path $cfg; \
    if (!(Test-Path $dir)) { New-Item -ItemType Directory -Path $dir -Force | Out-Null }; \
    $obj = if (Test-Path $cfg) { try { Get-Content $cfg -Raw -Encoding UTF8 | ConvertFrom-Json } catch { [PSCustomObject]@{} } } else { [PSCustomObject]@{} }; \
    if (-not ($obj.PSObject.Properties[\"mcpServers\"])) { $obj | Add-Member -MemberType NoteProperty -Name \"mcpServers\" -Value ([PSCustomObject]@{}) }; \
    $entry = [PSCustomObject]@{ command = \"$env:LOCALAPPDATA\Programs\dotward\resources\dotward-server.exe\"; args = @(\"mcp\") }; \
    $obj.mcpServers | Add-Member -MemberType NoteProperty -Name \"dotward\" -Value $entry -Force; \
    $obj | ConvertTo-Json -Depth 10 | Set-Content -Path $cfg -Encoding UTF8"'
  Pop $1
!macroend
