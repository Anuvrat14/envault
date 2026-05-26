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
