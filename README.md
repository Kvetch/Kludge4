Kludge 4.x Readme
======

Multiple common forensics tools kludged together into an automated process for data collection and parsing

Dependencies
------------

1. Python 2.7 --> tkinter module required - default with Windows Python installer
2. Windows Admin access on local and remote target
3. WMIC access
4. sqlite Python update - required soon - updated sqlite module since the Python windows installer has an old version

Optional Deps
-------------

* LogParser -> if you want parsed Win7 EVTX Logs then install it on the analyst side.  The script will utilize it - LogParser is needed to process EVTX Event Logs.  _The exe and dll are used on the remote machine instead of your machine because I've had issues using LogParser on XP against Win7 logs and not everyone might run this on a >=Win7 box._
http://www.microsoft.com/en-us/download/details.aspx?id=24659

* Volatility 2.x -> if you want to analyze the memory via the script

* RegRipper -> if you want to regrip stuff select the rip.exe when the script asks for it

What it does and how it works
------------------------------

#####Run the kludge.py file (Python should be in your PATH):

    python kludge.py

#####Supply the GUI with the IP address or name of the machine you wish to collect information on:

#####Select the Options you are interested in:

>> __Dump Memory__ - uses windd32/64 to dump memory on remote machine.  Copies memory back over while script is still collecting data to "hopefully" save a little time.
    
>> __Collect Mail Files__ - Should grab all PST, OST, OAB and NSF Files from User home dirs. (Warning can generate some huge files
    
>> __Record this incident for tracking purposes__ - This Option will record the machinename,date,a ticket number,and the analyst's name to a user selected csv file -> BLAH7X86,05-21-2012,86753o9,nick
    
>> __GPG Encryption, GPG UID, GPG Public Key__ - Will GPG encrypted the CollectedData and transfer the encrypted files.  You will need to create a GPG key on this machine and export the public key.  Script will encrypt the collected data using your exported pub key so you can unencrypt with your private key.  See below for details.
    
>> __Baseline Comparision Checks and Select Baseline Comparison Folder__ - Select the DIR that holds the collected data from a clean machine with the same OS.
_The thought here is to run the script against a known clean similar machine and same OS and save the unzipped Collected Data.  Then when you are analyzing a machine you believe may have an issue then you can select this check and it will compare items such as Dlls, AutoRuns, Codecs, AddOns, LSA, Startup and Services.  NOTE:  This isn't perfect and it still needs some work, so I can ignore things like PID #s that are probably different.  But in the meantime this hopefully cleans out some of the clutter one looks at when reviewing this data._
    
>> __Volatility Memory Analysis__ - Select the DIR where vol.py is located.  Yes, vol.py and not vol.exe.  This option is pointless if you haven't selected Dump Memory.
    
>> __RegRipper Analysis__ - Select the location of your "rip.exe" and the script will run a bunch of common RR plugins against the collected data.
   
>> __Detach Remote Process__ - If you are worried the remote machine will disconnect from the network and you want the script to still collect the data and zip it up then Select this option.  You will not see any output on the script besides the script checking to see if the zip files are available.  If you have launched the script and it is detached then you can kill Kludge and collect the zip files manually and parse them later or let it continue checking for the files.
    
>> __Create Report from Previous collection__ - If you manually collected the zipped collection data then you can select this option and choose the DIR that has the zip files.  If you have a memory dump put it in the same dir as the zip files.  You must enter in the machine name/IP address and select any options you had selected when the initial script was run.  Then you still select the DIR you want to house the Report and the unzipped data.  Then select Create Report from previous Kludge.
__NOTE: the DIR that houses the original zip files will be removed and the zip files will then reside in the DIR you selected via the "Report Directory" button.__
    
>> __Report Directory__ - Select the DIR you want all the data to be stored and the Report to be created.
    
#####Run Kludge:
>> __Run a new Kludge__ - runs a new instance of Kludge against a remote host

>> __Create Report from previous Kludge__ - runs only the parsing portion of Kludge against already collected Kludge files

Quick Overview
------------------

When Kludge is run, it will copy over a kludge.zip file on the remote host(\\remoteIP\c$\windows\temp\analysis), unzip and execute it's collection scripts(kludge-winxp.bat,kludge-win7.bat or kludge-win7x64.bat).

The data will be collected and zipped and then your machine will transfer the data back over, unencrypt, unzip, parse and create a bunch of html files with information regarding the collected data.

You can then view the html files for a brief way to review the data.

Data will be removed from the remote machine and the temporary scratch dir on your machine will be removed too (c:\windows\temp\IP-or-Name--timestamp)


Misc Notes
------------

To hopefully keep your password secure in memory(psexec) the script will first mount IPC$.  I "believe" psexec will utilize the established session instead of password prompting.

If you are accessing a remote machine with different credentials than the account you are using you should open a cmd window(run-as) as that user and run the script from the cmd window.  Especially if using a non-XP system

GPG Information
---------------

To create a gpg key and export a public key do the following:

    files/src/gpg --gen-key   (email address optional)

EXPORT a Public Key:

    files/src/gpg --export -a "User Name" > whatever-public.key