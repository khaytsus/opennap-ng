; opennap-ng.nsi
; optimised for NSIS 2.0b0
;
Name "opennap-ng_0.48"
OutFile "opennap-ng_0.48_i386.exe"
SetCompressor bzip2
InstallDir $PROGRAMFILES\opennap-ng
InstallDirRegKey HKLM SOFTWARE\opennap-ng "Install_Dir"

ComponentText "Thank you for choosing the Next Generation Open Source Napster Server! Please select which options you want installed."
DirText "Please choose a directory to install in to:"

LicenseText "Now I like this ;'). Please do read *all* of it! This is what Linux is all about..."
LicenseData "Copying"

AutoCloseWindow true
ShowInstDetails show

; Order of pages
Page license
Page custom SetCustom "" ": Username and Password"
Page components
Page directory
Page instfiles

; $7 = ini
Function .onInit
  SetOutPath $TEMP
  File /oname=spltmp.bmp "opennap-ng.bmp"
  splash::show 3000 $TEMP\spltmp
  Pop $0
  Delete $TEMP\spltmp.bmp
  Delete $TEMP\spltmp.wav
  GetTempFileName $7
  File /oname=$7 opennap-ng.ini
  File "release\mkpass.exe"
FunctionEnd

Function .onInstSuccess
  call Cleanup
FunctionEnd

Function .onInstFailed
  Call Cleanup
FunctionEnd

Function .onUserAbort
  Call Cleanup
FunctionEnd

Function Cleanup
  Delete $7
  Delete $TEMP\mkpass.exe
FunctionEnd

Function SetCustom
  IfFileExists $INSTDIR/users "done"
  InstallOptions::dialog $7
  Pop $0
  StrCmp $0 "cancel" done
  StrCmp $0 "back" done
  StrCmp $0 "success" 0 error
  goto done
  error:
  MessageBox MB_OK|MB_ICONSTOP "InstallOptions error: $\r$\n$0"
  done:
FunctionEnd

Section "Components"
  ReadINIStr $1 $7 "Field 4" "State"
  ReadINIStr $2 $7 "Field 5" "State"
SectionEnd

Section "opennap-ng (mandatory :)"
  SetOutPath $INSTDIR
  File "release\opennap.exe"
  File "release\setup.exe"
  File "release\mkpass.exe"
;  File "zlib.dll"
;  File "cygwin1.dll"
;  File "cygz.dll"
  IfFileExists $INSTDIR/config "skip1"
  	File /oname=config "config"
  skip1:
  IfFileExists $INSTDIR/motd "skip2"
  	File /oname=motd "motd"
  skip2:
  File "..\doc\manual.html"
  File "release\mkpass.exe"
  WriteRegStr HKLM SOFTWARE\opennap-ng "Install_Dir" "$INSTDIR"
  WriteRegStr HKLM "Software\Microsoft\Windows\CurrentVersion\Uninstall\opennap-ng" "DisplayName" "Opennap-NG (remove only)"
  WriteRegStr HKLM "Software\Microsoft\Windows\CurrentVersion\Uninstall\opennap-ng" "UninstallString" '"$INSTDIR\uninstall.exe"'
  WriteUninstaller "uninstall.exe"
  ReadINIStr $1 $7 "Field 4" "State"
  ReadINIStr $2 $7 "Field 5" "State"
  StrCmp $1 "" done
  StrCmp $2 "" done
  ExecWait '$TEMP\mkpass -n "$INSTDIR\users" -u $1 -p $2'
  done:
SectionEnd

Section "Start Menu Shortcuts"
  CreateDirectory "$SMPROGRAMS\Opennap-NG"
  CreateShortCut "$SMPROGRAMS\Opennap-NG\Uninstall.lnk" "$INSTDIR\uninstall.exe" "" "$INSTDIR\uninstall.exe" 0
  CreateShortCut "$SMPROGRAMS\Opennap-NG\Opennap-NG.lnk" "$INSTDIR\opennap.exe" "" "$INSTDIR\opennap.exe" 0
  CreateShortCut "$SMPROGRAMS\Opennap-NG\Setup.lnk" "$INSTDIR\setup.exe" "" "$INSTDIR\setup.exe" 0
  CreateShortCut "$SMPROGRAMS\Opennap-NG\Manual.lnk" "$INSTDIR\manual.html" "" "$INSTDIR\manual.html" 0
  CreateShortCut "$SMPROGRAMS\Opennap-NG\Edit Config.lnk" "c:\windows\notepad.exe" "$INSTDIR\config" "c:\windows\notepad.exe" 0
SectionEnd

UninstallText "This will uninstall Opennap-NG 0.48. Are You Sure??? It will delete *ALL* files in your opennap-ng dir."
Section "Uninstall"
  DeleteRegKey HKLM "Software\Microsoft\Windows\CurrentVersion\Uninstall\opennap-ng"
  DeleteRegKey HKLM SOFTWARE\opennap-ng
  Delete $INSTDIR\opennap.exe
  Delete $INSTDIR\setup.exe
  Delete $INSTDIR\mkpass.exe
;  Delete $INSTDIR\zlib.dll
;  Delete $INSTDIR\cygwin1.dll
;  Delete $INSTDIR\cygz.dll
  Delete $INSTDIR\config
  Delete $INSTDIR\users
  Delete $INSTDIR\servers
  Delete $INSTDIR\filter
  Delete $INSTDIR\block
  Delete $INSTDIR\motd
  Delete $INSTDIR\bans
  Delete $INSTDIR\channels
  Delete $INSTDIR\limit
  Delete $INSTDIR\pid
  Delete $INSTDIR\manual.html
  Delete $INSTDIR\uninstall.exe
  Delete "$SMPROGRAMS\Opennap-NG\*.*"
  RMDir "$SMPROGRAMS\Opennap-NG"
  RMDir "$INSTDIR"
SectionEnd

; eof
