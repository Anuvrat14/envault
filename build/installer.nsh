; Kill all Dotward processes at the very start of the installer
; customInit runs before the uninstall step - this is the key
!macro customInit
  nsExec::ExecToLog 'taskkill /F /IM "Dotward.exe" /T'
  nsExec::ExecToLog 'taskkill /F /IM "dotward-server.exe" /T'
  Sleep 2000
!macroend

!macro customUnInstall
  nsExec::ExecToLog 'taskkill /F /IM "Dotward.exe" /T'
  nsExec::ExecToLog 'taskkill /F /IM "dotward-server.exe" /T'
  Sleep 2000
!macroend
