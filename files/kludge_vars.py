import os, datetime
from os import *
import kludge_gui as gui
from codecs import BOM_UTF8, BOM_UTF16_BE, BOM_UTF16_LE, BOM_UTF32_BE, BOM_UTF32_LE

class KludgeVars:
	""" Kludge Global Variables"""
	def __init__(self):
		global option_level
		option_level = gui.StringVar()
		option_level.set(None)
		global BOMS
		BOMS = (
			(BOM_UTF8, "UTF-8"),
			(BOM_UTF32_BE, "UTF-32-BE"),
			(BOM_UTF32_LE, "UTF-32-LE"),
			(BOM_UTF16_BE, "UTF-16-BE"),
			(BOM_UTF16_LE, "UTF-16-LE"),
		)
		global optlevel
		optlevel = 2
		global dumpm
		dumpm = "no"
		global mailgrab
		mailgrab = "no"
		global gpg_enc
		gpg_enc = "no"
		global winver
		winver = "win7"
		global proctype
		proctype = "x86"
		global basecomp_run
		basecomp_run = "no"
		global vol_run
		vol_run = "no"
		global rr_run
		rr_run = "no"
		global now
		now = datetime.datetime.now()
		global timestmp
		timestmp = now.strftime("%m-%d-%Y_%H%M")
		global justdate
		justdate = now.strftime("%m-%d-%Y")
		global today
		today = datetime.datetime.today()
		global abitback
		abitback = (today - datetime.timedelta(days=30)).strftime("%m/%d/%Y")
		global rmt_ip
		rmt_ip = None
		global admin_act
		admin_act = None
		global anal_nam
		anal_name = None
		global ticket_num
		ticket_num = None
		global ticket_rec
		ticket_rec = "no"
		global detach
		detach = "no"
		# global dump_mem
		# dump_mem = gui.BooleanVar()
		# global record_inc
		# record_inc = gui.BooleanVar()
		global ir_trk
		ir_trk = "no"
		global riploc
		riploc = None
		global gpg_key
		gpg_key = None
		global vol_dir
		vol_dir = None
		global report_dir
		report_dir = None
		global gpg_uid
		gpg_uid = None
		global postrep
		postrep = "no"
		# global use_gpg
		# use_gpg = BooleanVar()
		global base_dir
		base_dir =None
		global rr_loc
		rr_loc = None
		global tmp_trgt_dir
		tmp_trgt_dir = None
		global gpgNames
		gpgNames = None
		global cname
		cname = None
		global outputdir
		outputdir = None
		global cmpnam
		cmpnam = None
		global memdone
		memdone = None
		global dir_names
		dir_names = ['SysInfo', 'DocsAndFiles', 'AV', 'NetInfo', 'Procs', 'Registry', 'TLN', 'Comparison', 'MemInfo', 'BrowserHistory']
		# This giant mother of a Hash Table contains the files collected from the remote host as the Key, the Value is the report html file name and the Title.  The Value is delimited with a <> cause I couldn't think of a better way to have 2 values associated to one Key without making two tables.  Split is used to seperate the Value and then [0] and [1] are set.
		global file2htmname
		file2htmname = {'SysInfo.csv': 'index.htm<>System', 'systeminfo.txt': 'index.htm<>System', 'WinVer.txt': 'index.htm<>System', 'PSInfo.csv': 'index.htm<>System', 'SetInfo.txt': 'osinfo.htm<>OS', 'OSInfo.csv': 'osinfo.htm<>OS', 'tickets.csv': 'tickets.htm<>Previous Ticket', 'DiskInfo.csv': 'driveinfo.htm<>Hard Drive', 'DriveInfo.csv': 'driveinfo.htm<>Hard Drive', 'PartInfo.csv': 'driveinfo.htm<>Hard Drive', 'Patches.csv': 'patches.htm<>Patches', 'HotFixes.csv': 'patches.htm<>Patches', 'Software.csv': 'software.htm<>Software', 'Shares.csv': 'shares_users.htm<>Shares and Users', 'PSLoggedOn.txt': 'shares_users.htm<>Shares and Users', 'LocalUsers.csv': 'shares_users.htm<>Shares and Users', 'AT.txt': 'misc.htm<>Miscellaneous', 'Clipboard.txt': 'misc.htm<>Miscellaneous', 'DOSKey.txt': 'misc.htm<>Miscellaneous', 'SchTasks.txt': 'misc.htm<>Miscellaneous', 'Quarantine.txt': 'av.htm<>AntiVirus', 'AVLog.txt': 'av.htm<>AntiVirus', 'Acrobat7.csv': 'acrobat.htm<>Acrobat', 'Acrobat8.csv': 'acrobat.htm<>Acrobat', 'Acrobat9.csv': 'acrobat.htm<>Acrobat', 'Acrobat10.csv': 'acrobat.htm<>Acrobat', 'Ads.txt': 'ads.htm<>Alternate Data Streams', 'RecycleBin.txt': 'recyclebin.htm<>RecycleBin', 'C-drive.txt': 'cdrive.htm<>C Drive', 'D-drive.txt': 'ddrive.htm<>D Drive', 'DocsSet.txt': 'docsset.htm<>Documents and Settings', 'E-drive.txt': 'edrive.htm<>E Drive', 'Firefox.csv': 'firefox.htm<>Firefox', 'Firefox-extensions.txt': 'firefox.htm<>Firefox', 'Firefox-pluginreg-dat.txt': 'firefox.htm<>Firefox', 'Firefox-mimeTypes-rdf.txt': 'firefox.htm<>Firefox', 'Firefox-extensions.txt': 'firefox.htm<>Firefox', 'Firefox-pluginreg-dat.txt': 'firefox.htm<>Firefox', 'Firefox-mimeTypes.txt': 'firefox.htm<>Firefox', 'Firefox-json.txt': 'firefox.htm<>Firefox', 'Firefox-prefsjs.txt': 'firefox.htm<>Firefox', 'Firefox-xpi.txt': 'firefox.htm<>Firefox', 'Firefox-key3db.txt': 'firefox.htm<>Firefox', 'Firefox-cdbfilesdb.txt': 'firefox.htm<>Firefox', 'Flash.csv': 'flash.htm<>Flash', 'JRE.txt': 'jre.htm<>JRE', 'MD5-Windows.txt': 'md5s.htm<>MD5', 'PerfLogs.txt': 'perflog.htm<>Perf Log', 'ProgData.txt': 'progdata.htm<>Program Data', 'ProgFilesDir.txt': 'progfiles.htm<>Program Files', 'Reader9.csv': 'acrobat.htm<>Acrobat', 'Reader10.csv': 'acrobat.htm<>Acrobat', 'acrobat.txt': 'acrobat.htm<>Acrobat', 'Recovery.txt': 'recovery.htm<>Recovery', 'UnSignedExes.txt': 'unsignedexes.htm<>UnSignedExes', 'Users.txt': 'userfiles.htm<>User Files', 'WindowsDir.txt': 'winfile.htm<>Windows Files', 'dlldump.txt': 'MemDllDump.htm<>Memory Dll Dump', 'dlllist.txt': 'memdlls.htm<>Memory Dlls', 'driverscan.txt': 'memdrivers.htm<>Memory Drivers', 'filescan.txt': 'memfile.htm<>Memory Files', 'getsids.txt': 'memsids.htm<>Memory Sids', 'handles.txt': 'Memhandles.htm<>Memory Handles', 'hivelist.txt': 'memhivelist.htm<>Memory Hive List', 'hivescan.txt': 'memhivescan.htm<>Memory Hive Scan', 'imageinfo.txt': 'meminfo.htm<>Memory', 'kdbgscan.txt': 'memkdbg.htm<>Memory KDBG', 'kpcrscan.txt': 'memkpcr.htm<>Memory KPCR', 'memmap.txt': 'memmap.htm<>Memory Map', 'modscan.txt': 'memmodscan.htm<>Memory ModScan', 'modules.txt': 'memmodules.htm<>Memory Modules', 'mutantscan.txt': 'MemMutant.htm<>Memory Mutant Scan', 'netscan.txt': 'memnetscan.htm<>Memory NetScan', 'pslist.txt': 'mempslist.htm<>Memory PSList', 'psscan.txt': 'mempsscan.htm<>Memory PSSScan', 'pstree.txt': 'mempstree.htm<>Memory PSTree', 'ssdt.txt': 'memssdt.htm<>Memory SSDT', 'thrdscan.txt': 'memthread.htm<>Memory Threads', 'vadinfo.txt': 'memvadinfo.htm<>Memory VAD', 'vadtree.txt': 'memvadtree.htm<>Memory VAD Tree', 'vadwalk.txt': 'memvadwalk.htm<>Memory VAD Walk', 'ARP.txt': 'routing.htm<>Routing', 'DNS.txt': 'dns.htm<>DNS', 'Firewall-Service.txt': 'firewall.htm<>Firewall', 'Firewall-State.txt': 'firewall.htm<>Firewall', 'Hosts.txt': 'dns.htm<>DNS', 'IPConfig.txt': 'routing.htm<>Routing', 'IPConfig-DNS.txt': 'dns.htm<>DNS', 'NBTStat.txt': 'netbios.htm<>NetBios', 'NetBios.txt': 'netbios.htm<>NetBios', 'NetBios-Sessions.txt': 'netbios.htm<>NetBios', 'NetStat.txt': 'tcpudp.htm<>TCP-UDP Connections', 'NIC.csv': 'nic.htm<>NIC', 'Route.txt': 'routing.htm<>Routing', 'TCPView.csv': 'tcpudp.htm<>TCP-UDP Connections', 'AutoRuns.csv': 'autorun.htm<>AutoRuns', 'AutoStart-Services.csv': 'autorun.htm<>AutoRuns', 'Codecs.csv': 'codecs.htm<>Codecs', 'Explorer-Addons.csv': 'exploreraddons.htm<>Explorer Addons', 'Gadgets.csv': 'gadgets.htm<>Gadgets', 'Handles.txt': 'handles.htm<>Handles', 'IE-AddOns.csv': 'ieaddons.htm<>IE Addons', 'Known-Dlls.csv': 'knowndlls.htm<>Known Dlls', 'ListDlls.txt': 'dlls.htm<>Running Dlls', 'LSA.csv': 'mischookproc.htm<>Miscellaneous Hooks', 'Printers.csv': 'printers.htm<>Printers', 'procs.csv': 'processes.htm<>Process', 'Prot-Net.csv': 'protnet.htm<>Process', 'Services.csv': 'autorun.htm<>AutoRuns', 'Startup.csv': 'autorun.htm<>AutoRuns', 'WinLogon.csv': 'winlogon.htm<>WinLogon', 'WSock32-Procs.txt': 'mischookproc.htm<>Miscellaneous Hooks', 'BHOs.txt': 'regbhos.htm<>BHOs', 'USBStor.txt': 'regusbstor.htm<>USBStor', 'acmru.txt': 'regntuser.htm<>Registry NTUser.dat', 'adobedr.txt': 'regntuser.htm<>Registry NTUser.dat', 'aim-ntuser.txt': 'regntuser.htm<>Registry NTUser.dat', 'aports.txt': 'regntuser.htm<>Registry NTUser.dat', 'appcompatflags.txt': 'regntuser.htm<>Registry NTUser.dat', 'applets.txt': 'regntuser.htm<>Registry NTUser.dat', 'arpcache.txt': 'regntuser.htm<>Registry NTUser.dat', 'autoendtasks.txt': 'regntuser.htm<>Registry NTUser.dat', 'autorun.txt': 'regntuser.htm<>Registry NTUser.dat', 'bagtest2.txt': 'regntuser.htm<>Registry NTUser.dat', 'bagtest.txt': 'regntuser.htm<>Registry NTUser.dat', 'bitbucket_user.txt': 'regntuser.htm<>Registry NTUser.dat', 'brisv.txt': 'regntuser.htm<>Registry NTUser.dat', 'cain.txt': 'regntuser.htm<>Registry NTUser.dat', 'clampitm.txt': 'regntuser.htm<>Registry NTUser.dat', 'comdlg32.txt': 'regntuser.htm<>Registry NTUser.dat', 'comdlg32a.txt': 'regntuser.htm<>Registry NTUser.dat', 'compdesc.txt': 'regntuser.htm<>Registry NTUser.dat', 'controlpanel.txt': 'regntuser.htm<>Registry NTUser.dat', 'cpldontload.txt': 'regntuser.htm<>Registry NTUser.dat', 'decaf.txt': 'regntuser.htm<>Registry NTUser.dat', 'dependency_walker.txt': 'regntuser.htm<>Registry NTUser.dat', 'domains.txt': 'regntuser.htm<>Registry NTUser.dat', 'environment.txt': 'regntuser.htm<>Registry NTUser.dat', 'fileexts.txt': 'regntuser.htm<>Registry NTUser.dat', 'gthist.txt': 'regntuser.htm<>Registry NTUser.dat', 'gtwhitelist.txt': 'regntuser.htm<>Registry NTUser.dat', 'haven_and_hearth.txt': 'regntuser.htm<>Registry NTUser.dat', 'ie_main.txt': 'regntuser.htm<>Registry NTUser.dat', 'ie_settings.txt': 'regntuser.htm<>Registry NTUser.dat', 'iexplore.txt': 'regntuser.htm<>Registry NTUser.dat', 'listsoft.txt': 'regntuser.htm<>Registry NTUser.dat', 'liveContactsGUID.txt': 'regntuser.htm<>Registry NTUser.dat', 'load.txt': 'regntuser.htm<>Registry NTUser.dat', 'logon_xp_run.txt': 'regntuser.htm<>Registry NTUser.dat', 'logonusername.txt': 'regntuser.htm<>Registry NTUser.dat', 'mmc.txt': 'regntuser.htm<>Registry NTUser.dat', 'mndmru.txt': 'regntuser.htm<>Registry NTUser.dat', 'mp2.txt': 'regntuser.htm<>Registry NTUser.dat', 'mpmru.txt': 'regntuser.htm<>Registry NTUser.dat', 'mspaper.txt': 'regntuser.htm<>Registry NTUser.dat', 'muicache.txt': 'regntuser.htm<>Registry NTUser.dat', 'nero.txt': 'regntuser.htm<>Registry NTUser.dat', 'netassist.txt': 'regntuser.htm<>Registry NTUser.dat', 'odysseus.txt': 'regntuser.htm<>Registry NTUser.dat', 'officedocs.txt': 'regntuser.htm<>Registry NTUser.dat', 'oisc.txt': 'regntuser.htm<>Registry NTUser.dat', 'outlook.txt': 'regntuser.htm<>Registry NTUser.dat', 'policies_u.txt': 'regntuser.htm<>Registry NTUser.dat', 'printermru.txt': 'regntuser.htm<>Registry NTUser.dat', 'printers.txt': 'regntuser.htm<>Registry NTUser.dat', 'privoxy.txt': 'regntuser.htm<>Registry NTUser.dat', 'proxysettings.txt': 'regntuser.htm<>Registry NTUser.dat', 'publishingwizard.txt': 'regntuser.htm<>Registry NTUser.dat', 'putty.txt': 'regntuser.htm<>Registry NTUser.dat', 'rdphint.txt': 'regntuser.htm<>Registry NTUser.dat', 'realplayer6.txt': 'regntuser.htm<>Registry NTUser.dat', 'realvnc.txt': 'regntuser.htm<>Registry NTUser.dat', 'recentdocs.txt': 'regntuser.htm<>Registry NTUser.dat', 'rootkit_revealer.txt': 'regntuser.htm<>Registry NTUser.dat', 'runmru.txt': 'regntuser.htm<>Registry NTUser.dat', 'sevenzip.txt': 'regntuser.htm<>Registry NTUser.dat', 'shellfolders.txt': 'regntuser.htm<>Registry NTUser.dat', 'skype.txt': 'regntuser.htm<>Registry NTUser.dat', 'snapshot_viewer.txt': 'regntuser.htm<>Registry NTUser.dat', 'startmenuinternetapps_cu.txt': 'regntuser.htm<>Registry NTUser.dat', 'startpage.txt': 'regntuser.htm<>Registry NTUser.dat', 'streammru.txt': 'regntuser.htm<>Registry NTUser.dat', 'streams.txt': 'regntuser.htm<>Registry NTUser.dat', 'tsclient.txt': 'regntuser.htm<>Registry NTUser.dat', 'typedpaths.txt': 'regntuser.htm<>Registry NTUser.dat', 'typedurls.txt': 'regntuser.htm<>Registry NTUser.dat', 'unreadmail.txt': 'regntuser.htm<>Registry NTUser.dat', 'user_run.txt': 'regntuser.htm<>Registry NTUser.dat', 'userassist2.txt': 'regntuser.htm<>Registry NTUser.dat', 'userassist.txt': 'regntuser.htm<>Registry NTUser.dat', 'userlocsvc.txt': 'regntuser.htm<>Registry NTUser.dat', 'vista_bitbucket.txt': 'regntuser.htm<>Registry NTUser.dat', 'vista_comdlg32.txt': 'regntuser.htm<>Registry NTUser.dat', 'vmplayer.txt': 'regntuser.htm<>Registry NTUser.dat', 'vmware_vsphere_client.txt': 'regntuser.htm<>Registry NTUser.dat', 'vnchooksapplicationprefs.txt': 'regntuser.htm<>Registry NTUser.dat', 'vncviewer.txt': 'regntuser.htm<>Registry NTUser.dat', 'wallpaper.txt': 'regntuser.htm<>Registry NTUser.dat', 'warcraft3.txt': 'regntuser.htm<>Registry NTUser.dat', 'win7_ua.txt': 'regntuser.htm<>Registry NTUser.dat', 'winlogon_u.txt': 'regntuser.htm<>Registry NTUser.dat', 'winrar.txt': 'regntuser.htm<>Registry NTUser.dat', 'winvnc.txt': 'regntuser.htm<>Registry NTUser.dat', 'winzip.txt': 'regntuser.htm<>Registry NTUser.dat', 'wordwheelquery.txt': 'regntuser.htm<>Registry NTUser.dat', 'yahoo_cu.txt': 'regntuser.htm<>Registry NTUser.dat', 'samparse2.txt': 'regsam.htm<>Registry SAM', 'samparse.txt': 'regsam.htm<>Registry SAM', 'auditpol.txt': 'regsecurity.htm<>Registry Security', 'lsasecrets.txt': 'regsecurity.htm<>Registry Security', 'polacdms.txt': 'regsecurity.htm<>Registry Security', 'appinitdlls.txt': 'regsoftware.htm<>Registry Software', 'apppaths.txt': 'regsoftware.htm<>Registry Software', 'assoc.txt': 'regsoftware.htm<>Registry Software', 'banner.txt': 'regsoftware.htm<>Registry Software', 'bho.txt': 'regsoftware.htm<>Registry Software', 'bitbucket.txt': 'regsoftware.htm<>Registry Software', 'clsid.txt': 'regsoftware.htm<>Registry Software', 'cmd_shell.txt': 'regsoftware.htm<>Registry Software', 'codeid.txt': 'regsoftware.htm<>Registry Software', 'ctrlpnl.txt': 'regsoftware.htm<>Registry Software', 'defbrowser.txt': 'regsoftware.htm<>Registry Software', 'drwatson.txt': 'regsoftware.htm<>Registry Software', 'ie_version.txt': 'regsoftware.htm<>Registry Software', 'imagefile.txt': 'regsoftware.htm<>Registry Software', 'init_dlls.txt': 'regsoftware.htm<>Registry Software', 'installedcomp.txt': 'regsoftware.htm<>Registry Software', 'javafx.txt': 'regsoftware.htm<>Registry Software', 'kb950582.txt': 'regsoftware.htm<>Registry Software', 'landesk.txt': 'regsoftware.htm<>Registry Software', 'macaddr.txt': 'regsoftware.htm<>Registry Software', 'mrt.txt': 'regsoftware.htm<>Registry Software', 'msis.txt': 'regsoftware.htm<>Registry Software', 'networkcards.txt': 'regsoftware.htm<>Registry Software', 'networklist.txt': 'regsoftware.htm<>Registry Software', 'networkuid.txt': 'regsoftware.htm<>Registry Software', 'notify.txt': 'regsoftware.htm<>Registry Software', 'port_dev.txt': 'regsoftware.htm<>Registry Software', 'product.txt': 'regsoftware.htm<>Registry Software', 'profilelist.txt': 'regsoftware.htm<>Registry Software', 'regback.txt': 'regsoftware.htm<>Registry Software', 'removedev.txt': 'regsoftware.htm<>Registry Software', 'renocide.txt': 'regsoftware.htm<>Registry Software', 'schedagent.txt': 'regsoftware.htm<>Registry Software', 'secctr.txt': 'regsoftware.htm<>Registry Software', 'sfc.txt': 'regsoftware.htm<>Registry Software', 'shellexec.txt': 'regsoftware.htm<>Registry Software', 'shellext.txt': 'regsoftware.htm<>Registry Software', 'shelloverlay.txt': 'regsoftware.htm<>Registry Software', 'snapshot.txt': 'regsoftware.htm<>Registry Software', 'soft_run.txt': 'regsoftware.htm<>Registry Software', 'specaccts.txt': 'regsoftware.htm<>Registry Software', 'sql_lastconnect.txt': 'regsoftware.htm<>Registry Software', 'ssid.txt': 'regsoftware.htm<>Registry Software', 'startmenuinternetapps_lm.txt': 'regsoftware.htm<>Registry Software', 'svchost.txt': 'regsoftware.htm<>Registry Software', 'taskman.txt': 'regsoftware.htm<>Registry Software', 'uninstall.txt': 'regsoftware.htm<>Registry Software', 'urlzone.txt': 'regsoftware.htm<>Registry Software', 'userinit.txt': 'regsoftware.htm<>Registry Software', 'virut.txt': 'regsoftware.htm<>Registry Software', 'vista_wireless.txt': 'regsoftware.htm<>Registry Software', 'win_cv.txt': 'regsoftware.htm<>Registry Software', 'win_ua.txt': 'regsoftware.htm<>Registry Software', 'winlogon.txt': 'regsoftware.htm<>Registry Software', 'winnt_cv.txt': 'regsoftware.htm<>Registry Software', 'winver.txt': 'regsoftware.htm<>Registry Software', 'yahoo_lm.txt': 'regsoftware.htm<>Registry Software', 'auditfail.txt': 'regsystem.htm<>Registry System', 'compname.txt': 'regsystem.htm<>Registry System', 'crashcontrol.txt': 'regsystem.htm<>Registry System', 'crashdump.txt': 'regsystem.htm<>Registry System', 'ddm.txt': 'regsystem.htm<>Registry System', 'devclass.txt': 'regsystem.htm<>Registry System', 'disablelastaccess.txt': 'regsystem.htm<>Registry System', 'dllsearch.txt': 'regsystem.htm<>Registry System', 'eventlog.txt': 'regsystem.htm<>Registry System', 'fw_config.txt': 'regsystem.htm<>Registry System', 'hibernate.txt': 'regsystem.htm<>Registry System', 'ide.txt': 'regsystem.htm<>Registry System', 'imagedev.txt': 'regsystem.htm<>Registry System', 'kbdcrash.txt': 'regsystem.htm<>Registry System', 'legacy.txt': 'regsystem.htm<>Registry System', 'mountdev2.txt': 'regsystem.htm<>Registry System', 'mountdev3.txt': 'regsystem.htm<>Registry System', 'mountdev.txt': 'regsystem.htm<>Registry System', 'network.txt': 'regsystem.htm<>Registry System', 'nic2.txt': 'regsystem.htm<>Registry System', 'nic.txt': 'regsystem.htm<>Registry System', 'nic_mst2.txt': 'regsystem.htm<>Registry System', 'nolmhash.txt': 'regsystem.htm<>Registry System', 'pagefile.txt': 'regsystem.htm<>Registry System', 'producttype.txt': 'regsystem.htm<>Registry System', 'rdpport.txt': 'regsystem.htm<>Registry System', 'routes.txt': 'regsystem.htm<>Registry System', 'safeboot.txt': 'regsystem.htm<>Registry System', 'services.txt': 'regsystem.htm<>Registry System', 'shares.txt': 'regsystem.htm<>Registry System', 'shutdown.txt': 'regsystem.htm<>Registry System', 'shutdowncount.txt': 'regsystem.htm<>Registry System', 'stillimage.txt': 'regsystem.htm<>Registry System', 'svc2.txt': 'regsystem.htm<>Registry System', 'svc.txt': 'regsystem.htm<>Registry System', 'svcdll.txt': 'regsystem.htm<>Registry System', 'termserv.txt': 'regsystem.htm<>Registry System', 'timezone2.txt': 'regsystem.htm<>Registry System', 'timezone.txt': 'regsystem.htm<>Registry System', 'usbdevices.txt': 'regsystem.htm<>Registry System', 'usbstor3.txt': 'regsystem.htm<>Registry System', 'usbstor.txt': 'regsystem.htm<>Registry System', 'xpedition.txt': 'regsystem.htm<>Registry System', 'timeline.txt': 'timeline.htm<>Timeline', 'autoruns-diff.csv': 'autorunsdiff.htm<>AutoRuns Diff', 'autosrvs-diff.csv': 'autorunsrvdiff.htm<>AutoRun Services Diff', 'codecs-diff.csv': 'codecsdiff.htm<>Codecs Diff', 'exaddons-diff.csv': 'exaddonsdiff.htm<>Explorer Addons Diff', 'ieaddons-diff.csv': 'ieaddonsdiff.htm<>IE Addons Diff', 'dll-diff.txt': 'dlldiff.htm<>Dlls Diff', 'knowndll-diff.csv': 'knowndllsdiff.htm<>Known Dlls Diff', 'lsa-diff.csv': 'lsadiff.htm<>LSA Diff', 'net-diff.csv': 'netdiff.htm<>Network Diff', 'services-diff.csv': 'servicesdiff.htm<>Services Diff', 'startup-diff.csv': 'startupdiff.htm<>Startup Diff'}
