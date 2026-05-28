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

  ; Fallback: write directly to ~/.claude/settings.json via PowerShell
  ; Note: $$ is the NSIS escape for a literal $ passed to the shell
  nsExec::ExecToLog 'powershell -NoProfile -NonInteractive -WindowStyle Hidden -Command \
    "$$p = Join-Path $$env:USERPROFILE \".claude\settings.json\"; \
    $$d = Split-Path $$p; \
    if (!(Test-Path $$d)) { New-Item -ItemType Directory -Path $$d -Force | Out-Null }; \
    $$o = if (Test-Path $$p) { try { Get-Content $$p -Raw -Encoding UTF8 | ConvertFrom-Json } catch { [PSCustomObject]@{} } } else { [PSCustomObject]@{} }; \
    if (-not ($$o.PSObject.Properties[\"mcpServers\"])) { $$o | Add-Member -MemberType NoteProperty -Name \"mcpServers\" -Value ([PSCustomObject]@{}) }; \
    $$e = [PSCustomObject]@{ command = \"$$env:LOCALAPPDATA\Programs\dotward\resources\dotward-server.exe\"; args = @(\"mcp\") }; \
    $$o.mcpServers | Add-Member -MemberType NoteProperty -Name \"dotward\" -Value $$e -Force; \
    $$o | ConvertTo-Json -Depth 10 | Set-Content -Path $$p -Encoding UTF8"'
  Pop $1
!macroend
