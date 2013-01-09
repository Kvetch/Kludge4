@echo off
REM Please email nick@theinterw3bs.com any changes or modifications to Kludge 4.0

REM Set the title to show what is running
title kludge-wmics.bat[start]

mkdir c:\windows\temp\analysis\temp
cd c:\windows\temp\analysis\temp
wmic.exe /output:temp.csv process list brief /format:csv

type temp.csv|more +1 >blah.csv

wmic.exe /output:temp.csv computersystem list full /format:csv

type temp.csv|more +1 >SysInfo.csv

wmic /output:temp.csv os get /all /format:csv

type temp.csv|more +1 >OSInfo.csv

wmic /output:temp.csv diskdrive list full /format:csv

type temp.csv|more +1 >DriveInfo.csv

wmic /output:temp.csv partition list full /format:csv

type temp.csv|more +1 >PartInfo.csv

wmic /output:temp.csv USERACCOUNT WHERE "Disabled=0 AND LocalAccount=1" GET Name /format:csv

type temp.csv|more +1 >LocalUsers.csv

wmic /output:temp.csv share list brief /format:csv

type temp.csv|more +1 >Shares.csv

wmic /output:temp.csv qfe list brief /format:csv

type temp.csv|more +1 >Patches.csv

wmic /output:temp.csv nic get /format:csv

type temp.csv|more +1 >NIC.csv

wmic /output:temp.csv process list full /format:csv

type temp.csv|more +1 >procs.csv

wmic /output:temp.csv service list brief /format:csv

type temp.csv|more +1 >Services.csv

wmic /output:temp.csv startup list /format:csv

type temp.csv|more +1 >Startup.csv

title kludge-wmics.bat[end]
