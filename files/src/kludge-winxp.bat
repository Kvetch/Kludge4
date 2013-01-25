@echo off
REM Please email nick@theinterw3bs.com any changes or modifications to Kludge 4.0

REM Set the title to show what is running
title kludge-winxp.bat[start]

cd c:\windows\temp\analysis
SETLOCAL EnableDelayedExpansion
mkdir SysInfo
echo.


REM Dump physical memory first
if %3 equ yes (
echo Dumping Physical Memory
echo done|.\win32dd.exe /m 0 /r /a /f c:\windows\temp\physmem-%COMPUTERNAME%.dump
mkdir MemInfo
REM move physmem-%COMPUTERNAME%.dump MemInfo\

REM Dump memory from each process
echo Dumping each Process' memory
reg ADD HKCU\Software\Sysinternals\ProcDump /v EulaAccepted /t REG_DWORD /d 1 /f
REM echo /output:blah.csv process list brief /format:csv | wmic.exe

type c:\windows\temp\analysis\temp\blah.csv > brief.txt
FOR /F "tokens=5 delims=," %%G IN (brief.txt) DO @echo %%G >> file.txt
.\grep.exe -v Process file.txt > pids.txt
FOR /F "tokens=*" %%G IN (pids.txt) DO procdump %%GMemInfo\%%G

if %2 equ yes (
echo.
echo Importing GPG Key
.\gpg.exe --import C:\Windows\Temp\analysis\pubkey.txt
FOR /F "tokens=*" %%G IN (C:\Windows\Temp\analysis\uid.txt) DO .\gpg.exe --always-trust --multifile --encrypt --recipient "%%G" C:\Windows\Temp\physmem*.dump
del C:\Windows\Temp\physmem*.dump
)
echo %date% - %time% > c:\windows\temp\analysis\mem-done.txt
)

REM Run Bastardized FLS version against a live C: drive.  Convert output into Timeline format.  Parse out the prefetch info into the Events file also.
if %1 geq 2 (
echo.
echo Gathering MFT against Local drives
echo.
type c:\windows\temp\analysis\temp\localdrivelist.txt > localdrivelist.txt
move /Y c:\windows\temp\analysis\temp\localdrivelist.txt SysInfo\
mkdir TLN
FOR /F "tokens=*" %%G IN (localdrivelist.txt) DO .\fls-live.exe %%G >> TLN\fls_bodyfile.txt
REM .\hmft.exe c: TLN\mft.dat
echo.
echo Running Pref against Prefetch Dir
.\pref.exe -d c:\windows\prefetch -t >> TLN\prefetch.txt

)

REM Create directories for the Report structure
mkdir Procs
mkdir NetInfo
mkdir Logs
mkdir BrowserHistory
mkdir Registry
mkdir DocsAndFiles
mkdir AV

REM REGISTRY ********************************************************************************************************************
REM Check Service Status and start if STATE equals STOPPED
echo.
echo Checking if VSS is started, if not starting VSS
sc query vss > vssstatus.txt
.\grep.exe STATE vssstatus.txt > vss.txt
set /p vssvar=<vss.txt
if "%vssvar%"== "        STATE              : 1  STOPPED " (
sc start vss
ping 127.0.0.1 -n 25 -w 1 >NUL
)


REM Copy Reg files and Event logs using Hobocopy
if %1 geq 2 (
echo.
echo Copying Registry, Profiles and Logs
REM For each directory in the Docs and Settings copy out it's ntuser.dat
echo.
echo Copying NTUser.dat and UsrClass files
cd "C:\Documents and Settings"
REM dir /b /a /q /s NTUSER.DAT > C:\Windows\Temp\analysis\ntuserdat.txt
dir /b /a /q /s UsrClass.DAT > C:\Windows\Temp\analysis\usrclassdat.txt
cd c:\windows\temp\analysis
REM call :LockorNot ntuserdat.txt Registry
call :LockorNot usrclassdat.txt Registry
FOR /F "tokens=*" %%G IN ('dir /b ^"C:\Documents and Settings\*^"') DO HoboCopy.exe "c:\Documents and Settings\%%G" Registry\%%G NTUSER.DAT
REM FOR /F "tokens=*" %%G IN ('dir /b ^"C:\Documents and Settings\*^"') DO HoboCopyWin7.exe "C:\Documents and Settings\%%G\Local Settings\Application Data\Microsoft\Windows" Registry\%%G UsrClass.dat


echo.
echo Copying UsrClass.dat files
REM For each directory in the Docs and Settings copy out it's usrclass.dat
REM FOR /F "tokens=*" %%G IN ('dir /b ^"C:\Documents and Settings\*^"') DO HoboCopy.exe "c:\Documents and Settings\%%G\Local Settings\Application Data\Microsoft\Windows" Registry\%%G UsrClass.dat

REM Copy the hives
echo.
echo Copying SAM Hive, logs and sav
.\HoboCopy.exe "C:\WINDOWS\system32\config" Registry\ SAM
REM .\HoboCopy.exe "C:\WINDOWS\system32\config" Registry\ SAM.log
REM .\HoboCopy.exe "C:\WINDOWS\system32\config" Registry\ SAM.sav

echo.
echo Copying Security Hive, logs and sav
.\HoboCopy.exe "C:\WINDOWS\system32\config" Registry\ SECURITY
REM .\HoboCopy.exe "C:\WINDOWS\system32\config" Registry\ SECURITY.log
REM .\HoboCopy.exe "C:\WINDOWS\system32\config" Registry\ SECURITY.sav

echo.
echo Copying Software Hive, logs and sav
.\HoboCopy.exe "C:\WINDOWS\system32\config" Registry\ SOFTWARE
REM .\HoboCopy.exe "C:\WINDOWS\system32\config" Registry\ SOFTWARE.log
REM .\HoboCopy.exe "C:\WINDOWS\system32\config" Registry\ SOFTWARE.sav

echo.
echo Copying System Hive, logs and sav
.\HoboCopy.exe "C:\WINDOWS\system32\config" Registry\ SYSTEM
REM .\HoboCopy.exe "C:\WINDOWS\system32\config" Registry\ SYSTEM.log
REM .\HoboCopy.exe "C:\WINDOWS\system32\config" Registry\ SYSTEM.sav

echo.
echo Copying Default Hive, logs and sav
.\HoboCopy.exe "C:\WINDOWS\system32\config" Registry\ default
REM .\HoboCopy.exe "C:\WINDOWS\system32\config" Registry\ default.log
REM .\HoboCopy.exe "C:\WINDOWS\system32\config" Registry\ default.sav

echo.
echo Copying UserDiff file and logs
.\HoboCopy.exe "C:\WINDOWS\system32\config" Registry\ userdiff
REM .\HoboCopy.exe "C:\WINDOWS\system32\config" Registry\ userdiff.log

echo.
echo Copying Event Logs
.\HoboCopy.exe "C:\WINDOWS\system32\config" Logs\ *.evt


REM NEED TO HOBOCOPY IE and FF and modify for Win7.
REM JUST COPYING NOW.  PASCO AND SQLITE WILL HAPPEN ON LOCAL SIDE
echo.
echo Copying Browser History
cd "c:\Documents and Settings"
REM dir /b /a * > C:\Windows\Temp\analysis\userlist.txt
dir /b /a /q /s index.dat > C:\Windows\Temp\analysis\historyfiles.txt
dir /b /a /q /s *.json >> C:\Windows\Temp\analysis\jsonfiles.txt
dir /b /a /q /s prefs.js >> C:\Windows\Temp\analysis\prefsjsfiles.txt
dir /b /a /q /s *.xpi >> C:\Windows\Temp\analysis\xpifiles.txt
dir /b /a /q /s extensions.ini >> C:\Windows\Temp\analysis\FF-extensions.txt
dir /b /a /q /s pluginreg.dat >> C:\Windows\Temp\analysis\FF-pluginreg.txt
dir /b /a /q /s mimeTypes.rdf >> C:\Windows\Temp\analysis\FF-mimeTypes.txt
dir /b /a /q /s key*.db >> C:\Windows\Temp\analysis\keydbfiles.txt
dir /b /a /q /s cert*.db >> C:\Windows\Temp\analysis\cdbfiles.txt
REM dir /b /a /q /s *.sqlite >> C:\Windows\Temp\analysis\sqlitefiles.txt
dir /b /a /q /s urlclassifier3.sqlite >> C:\Windows\Temp\analysis\urlclasssql.txt
dir /b /a /q /s OfflineCache\index.sqlite >> C:\Windows\Temp\analysis\offlinesql.txt
dir /b /a /q /s addons.sqlite >> C:\Windows\Temp\analysis\addonssql.txt
dir /b /a /q /s chromeappsstore.sqlite >> C:\Windows\Temp\analysis\chromeappsql.txt
dir /b /a /q /s content-prefs.sqlite >> C:\Windows\Temp\analysis\contentsql.txt
dir /b /a /q /s cookies.sqlite >> C:\Windows\Temp\analysis\cookiessql.txt
dir /b /a /q /s downloads.sqlite >> C:\Windows\Temp\analysis\downloadssql.txt
dir /b /a /q /s extensions.sqlite >> C:\Windows\Temp\analysis\ffextensionssql.txt
dir /b /a /q /s formhistory.sqlite >> C:\Windows\Temp\analysis\ffformhistorysql.txt
dir /b /a /q /s permissions.sqlite >> C:\Windows\Temp\analysis\ffpermissionssql.txt
dir /b /a /q /s places.sqlite >> C:\Windows\Temp\analysis\ffplacessql.txt
dir /b /a /q /s search.sqlite >> C:\Windows\Temp\analysis\ffsearchsql.txt
dir /b /a /q /s signons.sqlite >> C:\Windows\Temp\analysis\ffsignonssql.txt
dir /b /a /q /s webappsstore.sqlite >> C:\Windows\Temp\analysis\ffwebappsql.txt

cd C:\Windows\Temp\analysis
call :LockorNot historyfiles.txt index.dat

echo.
echo Copying Firefox Information
reg ADD HKCU\Software\Sysinternals\Strings /v EulaAccepted /t REG_DWORD /d 1 /f
FOR /F "tokens=*" %%M IN (C:\Windows\Temp\analysis\FF-extensions.txt) DO type "%%M" >> BrowserHistory\Firefox-extensions.txt
FOR /F "tokens=*" %%M IN (C:\Windows\Temp\analysis\FF-pluginreg.txt) DO type "%%M" >> BrowserHistory\Firefox-pluginreg-dat.txt
FOR /F "tokens=*" %%M IN (C:\Windows\Temp\analysis\FF-mimeTypes.txt) DO type "%%M" >> BrowserHistory\Firefox-mimeTypes.txt
FOR /F "tokens=*" %%M IN (C:\Windows\Temp\analysis\jsonfiles.txt) DO type "%%M" >> BrowserHistory\Firefox-json.txt
FOR /F "tokens=*" %%M IN (C:\Windows\Temp\analysis\prefsjsfiles.txt) DO type "%%M" >> BrowserHistory\Firefox-prefsjs.txt
FOR /F "tokens=*" %%L IN (C:\Windows\Temp\analysis\xpifiles.txt) DO .\strings.exe -n 13 "%%L" >> BrowserHistory\Firefox-xpi.txt
FOR /F "tokens=*" %%L IN (C:\Windows\Temp\analysis\keydbfiles.txt) DO .\strings.exe -n 5 "%%L" >> BrowserHistory\Firefox-key3db.txt
FOR /F "tokens=*" %%L IN (C:\Windows\Temp\analysis\cdbfiles.txt) DO .\strings.exe -n 5 "%%L" >> BrowserHistory\Firefox-cdbfilesdb.txt

call :LockorNot urlclasssql.txt urlclassifier3.sqlite
call :LockorNot offlinesql.txt OfflineCache\index.sqlite
call :LockorNot addonssql.txt addons.sqlite
call :LockorNot chromeappsql.txt chromeappsstore.sqlite
call :LockorNot contentsql.txt content-prefs.sqlite
call :LockorNot cookiessql.txt cookies.sqlite
call :LockorNot downloadssql.txt downloads.sqlite
call :LockorNot ffextensionssql.txt extensions.sqlite
call :LockorNot ffformhistorysql.txt formhistory.sqlite
call :LockorNot ffpermissionssql.txt permissions.sqlite
call :LockorNot ffplacessql.txt places.sqlite
call :LockorNot ffsearchsql.txt search.sqlite
call :LockorNot ffsignonssql.txt signons.sqlite
call :LockorNot ffwebappsql.txt webappsstore.sqlite



REM Export out the registry into reg text files
echo.
echo Outputting HKLM via reg cmd
reg export HKLM Registry\hklm.reg

echo.
echo Outputting HKCU via reg cmd
reg export HKCU Registry\hkcu.reg

echo.
echo Outputting HKCR via reg cmd
reg export HKCR Registry\hkcr.reg

echo.
echo Outputting HKU via reg cmd
reg export HKU Registry\hku.reg

echo.
echo Outputting HKCC via reg cmd
reg export HKCC Registry\hkcc.reg

REM END IF Option 2 or Greater
)

REM Write out the BHO's
echo.
echo Outputting Browser Helper Objects
reg query "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Browser Helper Objects" /s >> Registry\BHOs.txt


REM AV Info 
echo.
echo Copying SEP or McAfee AntiVirus Information
xcopy "C:\Documents and Settings\All Users\Application Data\Symantec\Symantec Antivirus Corporate Edition\7.5\Logs\*" AV\ /s /i /h /y
xcopy "C:\Documents and Settings\All Users\Application Data\Symantec\Symantec Endpoint Protection\Logs\*" AV\ /s /i /h /y
xcopy "C:\Documents and Settings\All Users\Application Data\McAfee\VirusScan\Logs\*.Log" AV\ /s /i /h /y
xcopy "C:\Documents and Settings\All Users\Application Data\McAfee\MSC\Logs\*.logs" AV\ /s /i /h /y
xcopy "C:\ProgramData\McAfee\MSC\Logs\*" AV\ /s /i /h /y

FOR /F "tokens=*" %%G IN ('dir /B /O-D ^"C:\Documents and Settings\All Users\Application Data\Symantec\Symantec Antivirus Corporate Edition\7.5\Logs\^"') DO type "C:\Documents and Settings\All Users\Application Data\Symantec\Symantec Antivirus Corporate Edition\7.5\Logs\%%G" >> AV\AVLog.txt
FOR /F "tokens=*" %%G IN ('dir /B /O-D ^"C:\Documents and Settings\All Users\Application Data\Symantec\Symantec Endpoint Protection\Logs\^"') DO type "C:\Documents and Settings\All Users\Application Data\Symantec\Symantec Endpoint Protection\Logs\%%G" >> AV\AVLog.txt
FOR /F "tokens=*" %%G IN ('dir /B /O-D ^"C:\Documents and Settings\All Users\Application Data\McAfee\VirusScan\Logs\*.Log^"') DO type "C:\Documents and Settings\All Users\Application Data\McAfee\VirusScan\Logs\%%G" >> AV\AVLog.txt
FOR /F "tokens=*" %%G IN ('dir /B /O-D ^"C:\Documents and Settings\All Users\Application Data\McAfee\MSC\Logs\*.logs^"') DO type "C:\Documents and Settings\All Users\Application Data\McAfee\MSC\Logs\%%G" >> AV\AVLog.txt
FOR /F "tokens=*" %%G IN ('dir /B /O-D ^"C:\ProgramData\McAfee\MSC\Logs\^"') DO type "C:\ProgramData\McAfee\MSC\Logs\%%G" >> AV\AVLog.txt


REM System Info
echo.
echo Outputting System Information
set >> SysInfo\SetInfo.txt
echo %PATH% >> SysInfo\SetInfo.txt

REM Output System Information via PSInfo
echo.
echo Running SysInternals PSInfo
reg ADD HKCU\Software\Sysinternals\PsInfo /v EulaAccepted /t REG_DWORD /d 1 /f
.\psinfo.exe -c >> SysInfo\PSInfo.csv

REM Output System Information via PSInfo
echo.
echo Outputting Installed Software via PSInfo
.\psinfo.exe -s -c >> DocsAndFiles\Software.csv

REM Output System Information via PSInfo
echo.
echo Outputting Disk Information via PSInfo
.\psinfo.exe -d -c >> SysInfo\DiskInfo.csv

REM Output System Information via PSInfo
echo.
echo Outputting Hotfixes via PSInfo
.\psinfo.exe -h -c >> SysInfo\HotFixes.csv

REM Output System Information via wmic
echo.
echo Moving System Information from wmic to proper path
move /Y c:\windows\temp\analysis\temp\SysInfo.csv SysInfo\
REM echo /output:SysInfo\SysInfo.csv computersystem list full /format:csv | wmic.exe

REM Output the OS Info via wmic
echo.
echo Moving OS Information from wmic to proper path
move /Y c:\windows\temp\analysis\temp\OSInfo.csv SysInfo\
REM echo /output:SysInfo\OSInfo.csv os get /all /format:csv | wmic

REM Write out Drive Info via wmic
echo.
echo Moving Drive and Partition Information from wmic to proper path
move /Y c:\windows\temp\analysis\temp\DriveInfo.csv SysInfo\
move /Y c:\windows\temp\analysis\temp\PartInfo.csv SysInfo\
REM wmic /output:SysInfo\DriveInfo.csv diskdrive list full /format:csv
REM wmic /output:SysInfo\PartInfo.csv partition list full /format:csv

REM Write out the usbstor data
echo.
echo Outputting USBStor data
reg query "HKLM\System\CurrentControlSet\Enum\USBSTOR" /s >> Registry\USBStor.txt

REM Write out local accounts
echo.
echo Moving local accounts list to proper path
REM wmic /output:SysInfo\LocalUsers.csv USERACCOUNT WHERE "Disabled=0 AND LocalAccount=1" GET Name /format:csv
move /Y c:\windows\temp\analysis\temp\LocalUsers.csv SysInfo\

REM Write out logged on users via psloggedon
echo.
echo Running SysInternals PSLoggedon
reg ADD HKCU\Software\Sysinternals\loggedon /v EulaAccepted /t REG_DWORD /d 1 /f
.\psloggedon >> SysInfo\PSLoggedOn.txt

REM Write out shares
echo Moving wmic Share information to proper path
move /Y c:\windows\temp\analysis\temp\Shares.csv SysInfo\
REM wmic /output:SysInfo\Shares.csv share list brief /format:csv

REM Write out Scheduled Tasks via schtask and at
echo.
echo Outputting Scheduled Tasks via schtasks
schtasks.exe /query >> SysInfo\SchTasks.txt
echo.
echo Outputting Scheduled Tasks via at
at.exe >> SysInfo\AT.txt

echo.
echo Outputting Clipboard (nothing there if running remotely)
.\pclip.exe >> SysInfo\Clipboard.txt
echo.
echo Outputting DOS History (nothing there is running remotely and no open windows)
doskey /history >> SysInfo\DOSKey.txt

REM Write out all hotfixes and SPs
echo.
echo Moving All Hotfixes/KBs and Service Packs information to proper path
REM wmic /output:SysInfo\Patches.csv qfe list brief /format:csv
move /Y c:\windows\temp\analysis\temp\Patches.csv SysInfo\


echo.
echo Running SysInternals TCPView
reg ADD HKCU\Software\Sysinternals\TCPView /v EulaAccepted /t REG_DWORD /d 1 /f
.\tcpvcon.exe -anc >> NetInfo\TCPView.csv

echo.
echo Outputting TCP/UDP Connections via netstat
netstat.exe -bona >> NetInfo\NetStat.txt

echo.
echo Outputting DNS Entries
ipconfig.exe /displaydns | findstr "Name Live Host" >> NetInfo\DNS.txt

REM Write out Hosts file
echo.
echo Outputting Hosts file
type c:\windows\system32\drivers\etc\hosts  >> NetInfo\Hosts.txt

REM Write out ipconfig information
echo.
echo Outputting IPConfig Information
ipconfig.exe ^/all >> NetInfo\IPConfig.txt
ipconfig.exe ^/displaydns >> NetInfo\IPConfig-DNS.txt

REM Write out ARP info
echo.
echo Outputting ARP Information
arp.exe -a >> NetInfo\ARP.txt

REM Write out current route conf
echo.
echo Outputting Routes
route.exe print >> NetInfo\Route.txt

REM Write out firewall state if enabled
echo.
echo Outputting Firewall Information
netsh.exe firewall show state >> NetInfo\Firewall-State.txt
netsh.exe firewall show service >> NetInfo\Firewall-Service.txt

REM Write out Network Adapter info 
echo.
echo Moving NIC Information to proper path
REM wmic /output:NetInfo\NIC.csv nic get /format:csv
move /Y c:\windows\temp\analysis\temp\NIC.csv NetInfo\

REM Write out any live NetBios connections
echo.
echo Outputting NetBios Information
net.exe use >> NetInfo\NetBios.txt

REM Write out NBTStat Info, NetBios over TCP Connections, Cache and Resolution
echo.
echo Outputting NBTStat Information
nbtstat.exe -nrSsc >> NetInfo\NBTStat.txt

REM Write out NetBios Session Info
echo.
echo Outputting NetBios Sessions
net.exe sessions >> NetInfo\NetBios-Sessions.txt

REM PROCS 
REM Write out all running Processes via wmic
echo.
echo Outputting all running Processes via wmic
REM wmic /output:Procs\procs.csv process list full /format:csv
move /Y c:\windows\temp\analysis\temp\procs.csv Procs\

REM Write out all processes using wsock32 via tasklist
echo.
echo All Processess using wsock32 via TaskList
tasklist -m wsock32.dll >> Procs\WSock32-Procs.txt
tasklist -m ws2_32.dll >> Procs\WS2_32-Procs.txt
tasklist -m wininet.dll >> Procs\WinInet-Procs.txt
tasklist -m ntdll.dll >> Procs\NTDll-Procs.txt

REM Write out startup apps via wmic
echo.
echo Outputting Startup Information via wmic
REM wmic /output:Procs\Startup.csv startup list /format:csv
move /Y c:\windows\temp\analysis\temp\Startup.csv Procs\

REM Write out autoruns via autorunsc
echo.
echo Outputting AutoRuns via AutoRunsC
reg ADD HKCU\Software\Sysinternals\Autoruns /v EulaAccepted /t REG_DWORD /d 1 /f
.\autorunsc.exe -ac >> Procs\AutoRuns.csv

REM Write out autoruns via autorunsc
echo.
echo Outputting Explorer Add-Ons via AutoRunsC
.\autorunsc.exe -ec >> Procs\Explorer-Addons.csv

REM Write out autoruns via autorunsc
echo.
echo Outputting SideBar Gadgets via AutoRunsC
.\autorunsc.exe -gc >> Procs\Gadgets.csv

REM Write out autoruns via autorunsc
echo.
echo Outputting Internet Explorer AddOns via AutoRunsC
.\autorunsc.exe -ic >> Procs\IE-AddOns.csv

REM Write out autoruns via autorunsc
echo.
echo Outputting Known Dlls via AutoRunsC
.\autorunsc.exe -kc >> Procs\Known-Dlls.csv

REM Write out autoruns via autorunsc
echo.
echo Outputting WinSock Protocol and Network Providers via AutoRunsC
.\autorunsc.exe -nc >> Procs\Prot-Net.csv

REM Write out autoruns via autorunsc
echo.
echo Outputting Codecs via AutoRunsC
.\autorunsc.exe -oc >> Procs\Codecs.csv

REM Write out autoruns via autorunsc
echo.
echo Outputting Printer Dlls via AutoRunsC
.\autorunsc.exe -pc >> Procs\Printers.csv

REM Write out autoruns via autorunsc
echo.
echo Outputting LSA Security Providers via AutoRunsC
.\autorunsc.exe -rc >> Procs\LSA.csv

REM Write out autoruns via autorunsc
echo.
echo Outputting AutoStart Services via AutoRunsC
.\autorunsc.exe -sc >> Procs\AutoStart-Services.csv

REM Write out autoruns via autorunsc
echo.
echo Outputting WinLogon Entries via AutoRunsC
.\autorunsc.exe -wc >> Procs\WinLogon.csv

echo.
echo Moving Services via wmic to proper path
REM wmic /output:Procs\Services.csv service list brief /format:csv
move /Y c:\windows\temp\analysis\temp\Services.csv Procs\

REM Write out all running dlls via listdlls
if %1 geq 2 (
echo.
echo Outputting all running dlls via SysInternals ListDlls
reg ADD HKCU\Software\Sysinternals\ListDLLs /v EulaAccepted /t REG_DWORD /d 1 /f
.\listdlls.exe >> Procs\ListDlls.txt

REM Write out all handles
echo.
echo Outputting all Handles via SysInternals Handles
reg ADD HKCU\Software\Sysinternals\Handle /v EulaAccepted /t REG_DWORD /d 1 /f
.\handle.exe -a -u > Procs\Handles.txt
)

REM Write out Browsing History
REM FOR /F "tokens=*" %%G IN ('dir /b ^"C:\Documents and Settings\*^"') DO xcopy "c:\Documents and Settings\%%G\Local Settings\History\*" BrowserHistory\%%G-History /s /i /h /y


REM Copy over all Flash Cookies
REM FOR /F "tokens=*" %%G IN ('dir /b ^"C:\Documents and Settings\*^"') DO xcopy "c:\Documents and Settings\%%G\Application Data\Macromedia\Flash Player\*" BrowserHistory\%%G-FlashCookies /s /i /h /y



REM DocsAndFiles
echo.
echo Outputting Adobe Acrobat, Adobe Reader, Flash and Java Version Information
reg ADD HKCU\Software\Sysinternals\SigCheck /v EulaAccepted /t REG_DWORD /d 1 /f
.\sigcheck.exe -q -e -v "C:\Program Files\Adobe\Reader 9.0\Reader\AcroRd32.exe" >> DocsAndFiles\Reader9.csv
.\sigcheck.exe -q -e -v "C:\Program Files\Adobe\Reader 10.0\Reader\AcroRd32.exe" >> DocsAndFiles\Reader10.csv
.\sigcheck.exe -q -e -v "C:\Program Files\Adobe\Acrobat 7.0\Acrobat\Acrobat.exe" >> DocsAndFiles\Acrobat7.csv
.\sigcheck.exe -q -e -v "C:\Program Files\Adobe\Acrobat 8.0\Acrobat\Acrobat.exe" >> DocsAndFiles\Acrobat8.csv
.\sigcheck.exe -q -e -v "C:\Program Files\Adobe\Acrobat 9.0\Acrobat\Acrobat.exe" >> DocsAndFiles\Acrobat9.csv
.\sigcheck.exe -q -e -v "C:\Program Files\Adobe\Acrobat 10.0\Acrobat\Acrobat.exe" >> DocsAndFiles\Acrobat10.csv
.\sigcheck.exe -q -e -v "c:\WINDOWS\system32\Macromed\Flash\Flash*" >> DocsAndFiles\Flash.csv
.\sigcheck.exe -q -e -v "C:\Program Files\Mozilla Firefox\firefox.exe" >> DocsAndFiles\Firefox.csv

reg query "HKLM\SOFTWARE\JavaSoft\Java Runtime Environment" /s >> DocsAndFiles\JRE.txt

if %1 equ 3 (
echo.
echo Outputting Unsigned Exes/Dlls in the System32
sigcheck -u -e c:\windows\system32 >> DocsAndFiles\UnSignedExes.txt
)

REM Write all files in Prog Files, Doc and Set, Windows, SAV/McAfee Quarantine
echo.
echo Outputting Directory Listing for Program Files, ProgramData, Docs&Settings, Users, Windows, PerfLogs, Recovery, C:, D:, E:, SAV, SEP and McAfee Quarantine.
dir /S /A /Q "C:\Program Files" >> DocsAndFiles\ProgFilesDir.txt
dir /S /A /Q "C:\ProgramData" >> DocsAndFiles\ProgData.txt
dir /S /A /Q "C:\Documents and Settings">> DocsAndFiles\DocsSet.txt
dir /S /A /Q "C:\Users">> DocsAndFiles\Users.txt
dir /S /A /Q "C:\Windows">> DocsAndFiles\WindowsDir.txt
dir /S /A /Q "C:\PerfLogs">> DocsAndFiles\PerfLogs.txt
dir /S /A /Q "C:\Recovery">> DocsAndFiles\Recovery.txt
dir /A /Q "C:\">> DocsAndFiles\C-drive.txt
dir /S /A /Q "D:">> DocsAndFiles\D-drive.txt
dir /S /A /Q "E:">> DocsAndFiles\E-drive.txt
dir /S /A /Q "C:\Documents and Settings\All Users\Application Data\Symantec\Symantec Antivirus Corporate Edition\7.5\Quarantine" >> AV\Quarantine.txt
dir /S /A /Q "C:\Documents and Settings\All Users\Application Data\Symantec\Symantec Endpoint Protection\Quarantine" >> AV\Quarantine.txt
dir /S /A /Q "C:\Documents and Settings\All Users\Application Data\McAfee\VirusScan\Quarantine" >> AV\Quarantine.txt

REM Write out RecycleBin Contents and Parse into the Timeline Events
if %1 geq 2 (
echo.
echo Outputting RecycleBin Contents
dir /b /a /AD c:\RECYCLER > dirlist.txt
FOR /F "tokens=*" %%G IN (dirlist.txt) DO rifiuti.exe c:\RECYCLER\%%G\INFO2 >> DocsAndFiles\RecycleBin.txt
del dirlist.txt
FOR /F "tokens=*" %%G IN (dirlist.txt) DO recbin.exe -i c:\RECYCLER\%%G\INFO2 -t >> TLN\events.txt

            )

REM Write out all Alternate Data Streams
if %1 equ 3 ( 
echo.
echo Outputting Alternate Data Streams
reg ADD HKCU\Software\Sysinternals\Streams /v EulaAccepted /t REG_DWORD /d 1 /f
.\streams.exe -s c:\ >> DocsAndFiles\Ads.txt

REM Write out hashes of Docs and Sets and Windows Directories
echo.
echo Outputting MD5s for the Windows Directory
.\md5deep -r -s -l -t c:\windows >> DocsAndFiles\MD5-Windows.txt

REM ################################################################################################
REM if "%winxp%" equ "yes" (
REM .\md5deep -r -s -l -t "C:\Documents and Settings" >> DocsAndFiles\MD5-DocsSet.txt
REM )

REM if "%win7%" equ "yes" (
REM .\md5deep -r -s -l -t "C:\Users" >> DocsAndFiles\MD5-Users.txt
REM )

)

if %4 equ yes (
echo Collecting Mail Files -- PST, OST, OAB and NSF Files
mkdir c:\windows\temp\analysis\Mail
Collecting OutLook Files
cd C:\Documents and Settings
dir /b /a /q /s *.pst >> C:\Windows\Temp\analysis\mail-files.txt
dir /b /a /q /s *.ost >> C:\Windows\Temp\analysis\mail-files.txt
dir /b /a /q /s *.oab >> C:\Windows\Temp\analysis\mail-files.txt
cd c:\Lotus
dir /b /a /q /s *.nsf >> C:\Windows\Temp\analysis\mail-files.txt
cd C:\Windows\Temp\analysis
call :LockorNot mail-files.txt Mail
)

REM Reset the Volume Shadow Service to it's stopped state if it wasn't initially running
echo.
echo Stopping VSS if it was stopped when starting collection
set /p vssvar=<vss.txt
if "%vssvar%"== "        STATE              : 1  STOPPED " (
sc stop vss
)

REM Zip up Report and Dirs into 10MB files CollectedData-<COMPUTERNAME>.zip.001 ..002 ..003, use 7Zip or WinRar to extract *********************************************************************************************************
REM rmdir /s /q plugins

if %1 equ 1 echo.
if %1 equ 1 echo Zipping up Information into a single zip file
if %1 equ 1 c:\windows\temp\7za.exe a -tzip -mx7 C:\Windows\Temp\CollectedData-%COMPUTERNAME%.zip *MemInfo *.html *SysInfo *Procs *NetInfo *Logs *BrowserHistory *Registry *DocsAndFiles *AV *TLN *Mail

if %1 geq 2 (
echo.
echo Zipping up Information into a multiple zip files
c:\windows\temp\7za.exe a -tzip -mx7 -v20m C:\Windows\Temp\CollectedData-%COMPUTERNAME% *MemInfo *.html *SysInfo *Procs *NetInfo *Logs *BrowserHistory *Registry *DocsAndFiles *AV *TLN *Mail
)

if %2 equ yes (
echo.
echo Importing GPG Key
.\gpg.exe --import C:\Windows\Temp\analysis\pubkey.txt
echo.
echo Encrypting Report File(s)
FOR /F "tokens=*" %%G IN (C:\Windows\Temp\analysis\uid.txt) DO .\gpg.exe --always-trust --multifile --encrypt --recipient "%%G" C:\Windows\Temp\CollectedData-%COMPUTERNAME%.*
REM FOR /F "tokens=*" %%G IN (C:\Windows\Temp\analysis\uid.txt) DO .\gpg.exe --always-trust --multifile --encrypt --recipient "%%G" C:\Windows\Temp\physmem*.dump
REM del C:\Windows\Temp\physmem*.dump
REM mkdir c:\windows\temp\gnupg
REM move c:\windows\temp\*.gpg c:\windows\temp\gnupg\
)

REM Write a file called done.txt so the Analyst's side knows the script is finished
REM echo.
REM echo Sleeping for 20 seconds
REM ping 127.0.0.1 -n 20 -w 1 >NUL
REM echo.
echo Writing out done.txt
echo %date% - %time% > c:\windows\temp\analysis\done.txt

title kludge-winxp.bat[end]

GOTO :eof
REM END OF SCRIPT *******************************************************************************************************************



:LockorNot
@echo %1
@echo %2
echo.
echo FOR /F "tokens=*" %%L IN (%1) DO echo.N|copy /-y NUL "%%L"
FOR /F "tokens=*" %%L IN (%1) DO echo.N|copy /-y NUL "%%L">NUL&&(
    @echo.%%L is not locked xcopying
    xcopy "%%L" "%2%%~pL" /Y /H
    rem test
) || (
	echo %%~pL%%~nL%%~xL is LOCKED
	echo%%~pL|.\sed.exe -e "s/\(.*\)../\1/">tempfile.txt
	set xfilepath=
	set /p xfilepath=<tempfile.txt
	echo "%xfilepath%"
	echo %%L
	echo .\HoboCopy.exe /y /skipdenied "C:\%xfilepath%" "%2\%xfilepath%" "%%~nL%%~xL"
	.\HoboCopy.exe /y /skipdenied "C:\%xfilepath%" "%2\%xfilepath%" "%%~nL%%~xL"
	set xfilepath=
)
GOTO :eof
