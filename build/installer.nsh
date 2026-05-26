; Kill any running Dotward instance before install/uninstall
!macro customInstall
  nsExec::ExecToLog 'taskkill /F /IM "Dotward.exe" /T'
  Sleep 1500
!macroend

!macro customUnInstall
  nsExec::ExecToLog 'taskkill /F /IM "Dotward.exe" /T'
  Sleep 1500
!macroend
