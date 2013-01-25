import tkFileDialog, time, os, subprocess, glob, datetime, thread, fnmatch, csv, sys, codecs
from Tkinter import *
from subprocess import *
import kludge_vars as vars

class Reporter(object):
	""" Report for Kludge"""
	def __init__(self):
		self = self
		self.create_report()
		
	def create_report(self):
		print("\n\n\n\nCreating the Report\n\n\n\n")
		call("mkdir " + vars.outputdir + "\\Report", shell=True)
		call("copy files\\templates\\kludge.css " + vars.outputdir + "\\Report\\ /Y", shell=True)
		self.finder()
		self.finish_all()
		
		
		
	def finder(self):
		for item in vars.dir_names:
			path = vars.outputdir + "\\" + item
			print("PATH " + path)
			for root, dir, files in os.walk(path):
				for file in files:
					self.file = file
					self.datafilepath = os.path.join(root, file)
					#print("IS THIS IT " + self.datafilepath)
					print("FILE " + self.file)
					if self.file in vars.file2htmname:
						ftitle = vars.file2htmname.get(self.file)
						print(str(ftitle))
						file_title = []
						file_title = ftitle.split('<>')
						self.reportfilename = str(file_title[0])
						self.name = str(file_title[1])
						#self.reportfilename = vars.file2htmname.get(self.file)
						print("REPORTFILENAME " + self.reportfilename)
						self.create_file()
					else:
						#print("NOTHING")
						print(" ")

	def create_file(self):
		self.fullreportfpath = vars.outputdir + "\\Report\\" + self.reportfilename
		print("Printing the fullreportfpath " + self.fullreportfpath)
		#self.find_name(htmname)
		if os.path.exists(self.fullreportfpath):
			print("Path exists")
			self.openfile = open(self.fullreportfpath, "a")
			self.add_content()
			
		else:
			self.openfile = open(self.fullreportfpath, "w")
			print("Path does not exist")
			print (self.openfile)
			self.create_header()
			self.create_leftrail()
			self.create_ctop()
			self.create_content()
				
	
	def create_header(self):
		self.openfile.writelines(["""<!DOCTYPE html PUBLIC "-//W3C//DTD XHTML 1.0 Transitional//EN" "http://www.w3.org/TR/xhtml1/DTD/xhtml1-transitional.dtd">\n""",
			"""<html xml:lang="en-US" xmlns="http://www.w3.org/1999/xhtml" lang="en-US"><head><title>Kludge """ + self.name + """ Information Collection on """ + vars.cname + """ </title>\n"""])
		self.openfile.writelines(["""<link rel="stylesheet" type="text/css" href="kludge.css" /></head><body> \n"""])
			
		self.openfile.writelines(["""<div style="position: relative; width: 100%; margin-top: 0px; margin-bottom: 0px;"> \n""",
			"""<a id="top"> \n""",
			"""</a><div style="width: 90%; margin-top: 5px; margin-left: auto; margin-right: auto;"> \n""",
			"""<div style="margin: 0pt; padding: 0pt; width: 100%; height: 74px;"> \n""",
			"""<div style="width: 28%; text-align: left; float: left;"> \n""",
			"""<h2><a id="top">""" + vars.cname + """</a></h2> \n""",
			"""<a id="top">	 \n""",
			"""</a></div> \n""",
			"""<div style="width: 40%; float: right; text-align: right; margin-top: 20px; margin-right: 14px; margin-bottom: 5px;"> \n""",
			"""<div id="translate_link" style="margin-bottom: 14px;"> \n""",
			"""<a class="topnav" href="http://www.google.com/cse/home?cx=011905220571137173365:7eskxxzhjj8" target="_blank">Digital Forensics Search</a> \n""",
			"""</div> \n""",
			"""	<form style="font-size: 11px;" method="get" name="searchform" action="http://www.google.com/cse" target="_blank" id="cse-search-box"> \n""",
			"""   	<input onfocus="searchfield_focus(this)" style="margin: 0pt; width: 150px; color: rgb(128, 128, 128); font-style: italic;" name="q" size="20" value="Digital Forensics Search" type="text" /> \n""",
			"""	<input name="cx" value="011905220571137173365:7eskxxzhjj8" type="hidden" /> \n""",
			"""	<input name="ie" value="UTF-8" type="hidden" /> \n""",
			"""	<input name="sa" style="margin: 0pt;" value="Search" title="Digital Forensics Search" type="submit" /> \n""",
			"""	</form> \n""",
			"""</div> \n""",
			"""</div> \n""",
			"""<div id="topnav" style="clear: both; width: 100%; height: 25px;"> \n""",
			"""<div style="float: left; width: 44%; word-spacing: 8px; font-size: 90%; padding-left: 15px; padding-top: 6px; white-space: nowrap; text-align: left;"> \n""",
			"""	<a class="topnav" href="index.htm" target="_top">System</a> \n""",
			"""	<a class="topnav" href="process.htm" target="_top">Process </a> \n""",
			"""	<a class="topnav" href="tcpudp.htm" target="_top">Network </a> \n""",
			"""	<a class="topnav" href="regbhos.htm" target="_top">Registry </a> \n""",
			"""	<a class="topnav" href="userfiles.htm" target="_top">Files </a> \n""",
			])
		if vars.vol_run == "yes":
			self.openfile.writelines(["""	<a class="topnav" href="memory.htm" target="_top">Memory </a> \n"""])
		if vars.optlevel >= 2:
			self.openfile.writelines(["""	<a class="topnav" href="timeline.htm" target="_top">Timeline </a> \n"""])
		self.openfile.writelines(["""	<a class="topnav" href="antivirus.htm" target="_top">AV </a> \n""",
			"""	<a class="topnav" href="logs.htm" target="_top">Logs </a> \n""",
			"""</div> \n""",
			"""</div> \n""",
			"""<div style="margin: 0px; padding: 0px; overflow: hidden; width: 100%; height: 45px; position: relative;"> \n""",
			"""<div style="margin: 0pt; padding: 0pt; overflow: hidden; width: 66%; height: 45px; position: relative; right: 0px; top: 0px;"> \n""",
			"""</div></div> \n""",
			])
		#self.openfile.close()

	def create_leftrail(self):
		self.openfile.writelines(["""<div style="margin: 0px; padding: 0px; width: 100%;"> \n""",
			"""<div id="leftcolumn" style="margin: 5px 0pt 0pt; padding: 0pt; width: 19%; float: left;"><h2 class="left"><span class="left_h2">System</span> Information</h2> \n""",
			"""<a target="_top" href="index.htm">System Information</a><br /> \n""",
			])
		if vars.ticket_rec == "yes":
			self.openfile.writelines(["""<a target="_top" href="tickets.htm">Previous Tickets</a><br /> \n"""])
		self.openfile.writelines(["""<a target="_top" href="osinfo.htm">OS Information</a><br /> \n""",
			"""<a target="_top" href="driveinfo.htm">Drive Information</a><br /> \n""",
			"""<a target="_top" href="patches.htm">Patches and Hotfixes</a><br /> \n""",
			"""<a target="_top" href="software.htm">Software Information</a><br /> \n""",
			"""<a target="_top" href="acrobat.htm">Acrobat Information</a><br /> \n""",
			"""<a target="_top" href="jre.htm">JRE Information</a><br /> \n""",
			"""<a target="_top" href="flash.htm">Flash Information</a><br /> \n""",
			"""<a target="_top" href="firefox.htm">Firefox Information</a><br /> \n""",
			"""<a target="_top" href="shares_users.htm">Shares and Users</a><br /> \n""",
			"""<a target="_top" href="misc.htm">Misc Information</a><br /> \n""",
			"""<br /> \n""",
			"""<h2 class="left"><span class="left_h2">Process</span> Information</h2> \n""",
			"""<a target="_top" href="processes.htm">Running Processes</a><br /> \n""",
			"""<a target="_top" href="autorun.htm">Startup Information</a><br /> \n""",
			"""<a target="_top" href="dlls.htm">Dlls</a><br /> \n""",
			"""<a target="_top" href="knowndlls.htm">Known Dlls</a><br /> \n""",
			"""<a target="_top" href="handles.htm">Handles</a><br /> \n""",
			])
		if vars.optlevel == 3:
			self.openfile.writelines(["""<a target="_top" href="unsignedexes.htm">UnSigned Exes</a><br /> \n"""])
		self.openfile.writelines(["""<a target="_top" href="printers.htm">Printers</a><br /> \n""",
			"""<a target="_top" href="lsa.htm">LSA** Information</a><br /> \n""",
			"""<a target="_top" href="winlogon.htm">WinLogon Information</a><br /> \n""",
			"""<a target="_top" href="mischookproc.htm">Misc Hooks &amp; Process Information</a><br /> \n""",
			"""<a target="_top" href="codecs.htm">Codecs</a><br /> \n""",
			"""<a target="_top" href="gadgets.htm">Gadgets</a><br /> \n""",
			"""<a target="_top" href="exploreraddons.htm">Explorer Addons</a><br /> \n""",
			"""<a target="_top" href="ieaddons.htm">IE Addons</a><br /> \n""",
			"""<br /> \n""",
			"""<h2 class="left"><span class="left_h2">Network</span> Information</h2> \n""",
			"""<a target="_top" href="tcpudp.htm">TCP/UDP Connections</a><br /> \n""",
			"""<a target="_top" href="protnet.htm">Protocols</a><br /> \n""",
			"""<a target="_top" href="dns.htm">DNS Information</a><br /> \n""",
			"""<a target="_top" href="routing.htm">Routing Information</a><br /> \n""",
			"""<a target="_top" href="nic.htm">Network Interface Information</a><br /> \n""",
			"""<a target="_top" href="netbios.htm">NetBios Information</a><br /> \n""",
			"""<a target="_top" href="firewall.htm">Firewall Information</a><br /> \n""",
			"""<br /> \n""",
			"""<h2 class="left"><span class="left_h2">Registry</span> Information</h2> \n""",
			"""<a target="_top" href="regusbstor.htm">USB Information</a><br /> \n""",
			"""<a target="_top" href="regbhos.htm">BHOs</a><br /> \n""",
			])
		if vars.rr_run == "yes":
			self.openfile.writelines(["""<a target="_top" href="regsystem.htm">System Hive Information</a><br /> \n""",
				"""<a target="_top" href="regntuser.htm">NTUSER.dat Information</a><br /> \n""",
				"""<a target="_top" href="regsoftware.htm">Software Hive Information</a><br /> \n""",
				"""<a target="_top" href="regsecurity.htm">Security Hive Information</a><br /> \n""",
				"""<a target="_top" href="regsam.htm">SAM Hive Information</a><br /> \n""",
				"""<a target="_top" href="jump.htm">Jump-Lists***</a><br /> \n""",
				])
				# """<a target="_top" href="txr.htm---TxR">TxR***</a><br /> \n""",
				# """<a target="_top" href="regback.htm---RegBack">RegBack***</a><br /> \n""",
				# """<a target="_top" href="sysprofile.htm---systemprofile">System Profile***</a><br /> \n""",
				# """<a target="_top" href="public.htm---Public">Public***</a><br /> \n""",
				# """<a target="_top" href="journal.htm---Journal">Journal***</a><br /> \n""",
				# """<a target="_top" href="default.htm---DEFAULT">Default***</a><br /> \n""",
				# """<a target="_top" href="components.htm---COMPONENTS">Components***</a><br /> \n""",
				# """<a target="_top" href="bcd.htm---BCD-Template">BCD-Template***</a><br /> \n""",
				
		self.openfile.writelines(["""<a target="_top" href=" """+ vars.outputdir + """\\Registry\\">Link to Reg Exports and Hives***</a><br /> \n""",
			"""<br /> \n""",
			"""<h2 class="left"><span class="left_h2">File</span> Information</h2> \n""",
			"""<a target="_top" href="userfiles.htm">User Files</a><br /> \n""",
			"""<a target="_top" href="docsset.htm">Docs and Settings</a><br /> \n""",
			"""<a target="_top" href="winfile.htm">Windows Files</a><br /> \n""",
			"""<a target="_top" href="progdata.htm">Program Data</a><br /> \n""",
			"""<a target="_top" href="progfiles.htm">Program Files</a><br /> \n""",
			"""<a target="_top" href="recovery.htm">Recovery Files</a><br /> \n""",
			"""<a target="_top" href="perflog.htm">Perf Logs</a><br /> \n""",
			"""<a target="_top" href="cdrive.htm">C Drive</a><br /> \n""",
			"""<a target="_top" href="ddrive.htm">D Drive</a><br /> \n""",
			"""<a target="_top" href="edrive.htm">E Drive</a><br /> \n""",
			"""<a target="_top" href="recyclebin.htm">RecycleBin Files</a><br /> \n""",
			"""<a target="_top" href=" """+ vars.outputdir + """\\Browser%20History\\">Link to Browser History Files</a><br /> \n""",
			])
		if vars.optlevel == 3:
			self.openfile.writelines(["""<a target="_top" href="ads.htm">Alternate Data Streams</a><br /> \n""",
				"""<a target="_top" href="md5s.htm">MD5s</a><br /> \n""",
				])
		if vars.vol_run == "yes":
			self.openfile.writelines(["""<br /> \n""",
				"""<h2 class="left"><span class="left_h2">Memory</span> Information</h2> \n""",
				"""<a target="_top" href="meminfo.htm">Memory Information</a><br /> \n""",
				"""<a target="_top" href="mempslist.htm">Memory PIDS Information</a><br /> \n""",
				])
			if vars.winver == "winxp":
				self.openfile.writelines(["""<a target="_top" href="memconnects.htm">Memory Connection Information</a><br /> \n""",
					"""<a target="_top" href="memconscan.htm">Memory ConnScan Information</a><br /> \n""",
					"""<a target="_top" href="memsockets.htm">Memory Sockets Information</a><br /> \n""",
					])
			if vars.winver == "win7":
				self.openfile.writelines(["""<a target="_top" href="memnetscan.htm">Memory NetScan Information</a><br /> \n"""])
			self.openfile.writelines(["""<a target="_top" href="mempstree.htm">Memory PS Tree Information</a><br /> \n""",
				"""<a target="_top" href="mempsscan.htm">Memory PS Scan Information</a><br /> \n""",
				"""<a target="_top" href="memdlls.htm">Memory DLL Information</a><br /> \n""",
				"""<a target="_top" href="Memhandles.htm">Memory Handles Information</a><br /> \n""",
				"""<a target="_top" href="memsids.htm">Memory SIDS Information</a><br /> \n""",
				"""<a target="_top" href="memverinfo.htm">Memory Version Information</a><br /> \n""",
				"""<a target="_top" href="memvadwalk.htm">Memory VAD Walk Information</a><br /> \n""",
				"""<a target="_top" href="memvadtree.htm">Memory VAD Tree Information</a><br /> \n""",
				"""<a target="_top" href="memvadinfo.htm">Memory VAD Information</a><br /> \n""",
				"""<a target="_top" href="memmodules.htm">Memory Modules Information</a><br /> \n""",
				"""<a target="_top" href="memmodscan.htm">Memory ModScan Information</a><br /> \n""",
				"""<a target="_top" href="memssdt.htm">Memory SSDT Information</a><br /> \n""",
				"""<a target="_top" href="memdrivers.htm">Memory Drivers Information</a><br /> \n""",
				"""<a target="_top" href="memfile.htm">Memory File Information</a><br /> \n""",
				"""<a target="_top" href="MemMutant.htm">Memory Mutant Scan</a><br /> \n""",
				"""<a target="_top" href="memthread.htm">Memory Threads Information</a><br /> \n""",
				"""<a target="_top" href="memhivescan.htm">Memory Hive Scan</a><br /> \n""",
				"""<a target="_top" href="memhivelist.htm">Memory Hive List Information</a><br /> \n""",
				])
		if vars.basecomp_run == "yes":
			self.openfile.writelines(["""<br /> \n""",
				"""<h2 class="left"><span class="left_h2">Comparision</span> Information</h2> \n""",
				"""<a target="_top" href="dlldiff.htm">Dll Comparison</a><br /> \n""",
				"""<a target="_top" href="autorunsdiff.htm">AutoRuns Base Comparison</a><br /> \n""",
				"""<a target="_top" href="autorunsrvdiff.htm">AutoRun Services Diff</a><br /> \n""",
				"""<a target="_top" href="codecsdiff.htm">Codecs Diff</a><br /> \n""",
				"""<a target="_top" href="exaddonsdiff.htm">Explorer Addons Diff</a><br /> \n""",
				"""<a target="_top" href="ieaddonsdiff.htm">IE Addons Diff</a><br /> \n""",
				"""<a target="_top" href="knowndllsdiff.htm">Known Dlls Diff</a><br /> \n""",
				"""<a target="_top" href="lsadiff.htm">LSA Diff</a><br /> \n""",
				"""<a target="_top" href="netdiff.htm">Network Diff</a><br /> \n""",
				"""<a target="_top" href="servicesdiff.htm">Services Diff</a><br /> \n""",
				"""<a target="_top" href="startupdiff.htm">Startup Comparison</a><br /> \n""",
				])
		if vars.optlevel >= 2:
			self.openfile.writelines(["""<br /> \n""",
				"""<h2 class="left"><span class="left_h2">Timeline</span> Information</h2> \n""",
				"""<a target="_top" href="timeline.htm">Timeline Files</a><br /> \n""",
				])
		self.openfile.writelines(["""<br /> \n""",
			"""<h2 class="left"><span class="left_h2">AV</span> Information</h2> \n""",
			"""<a target="_top" href="av.htm">Quarantine Files</a><br /> \n""",
			"""<a target="_top" href="avlogs.htm">AV Logs***</a><br /> \n""",
			"""<br /> \n""",
			"""<h2 class="left"><span class="left_h2">Log</span> Information</h2> \n""",
			"""<a target="_top" href=" """+ vars.outputdir + """\\Logs\\">Link to Logs***</a><br /> \n""",
			"""</div> \n""",
			])
		#self.openfile.close()
		#self.create_content()

	def create_ctop(self):
		#name = name
		self.openfile.writelines(["""<div style="margin: 0px; padding: 4px 5px 8px 0px; width: 80%; background-color: rgb(255, 255, 255); color: rgb(0, 0, 0); float: left;"> \n""",
			"""<h1>""" + vars.cname + """'s <span class="color_h1">""" + self.name + """ Information</span></h1> \n""",
			"""<hr /> \n""",
			"""<hr /> \n""",
			"""<br /> \n""",
			])

	def check_bom(self,data):
		return [encoding for bom, encoding in vars.BOMS if data.startswith(bom)]
	
	def create_content(self):
		print("jkhjkjkjhkjhk")
		#filepath = self.filepath
		#file = self.file
		#name = name
		if self.file.find('.csv') != -1:
			type = 'csv'
		else:
			type = 'txt'
		if type == 'txt':
			# DON'T DO THE NEXT LINE FOR APPEND.  I THINK IT WILL CREATE AN EXTRA TABLE BUT DO THE H2 LINE
			self.openfile.writelines(["""<table class="nonparsed" border="0" cellpadding="0" cellspacing="0" width="100%"><tbody><tr><td> \n""",
				"""<h2 class="nonparsed_content"> <a href="file:///""" + self.datafilepath + """">""" + self.file + """</a> </h2></td></tr>"""])
			self.openfile.writelines(["""<table class="nonparsed_content" border="1" cellpadding="5" cellspacing="5" width="100%"><tbody><tr><td><pre><code>\n"""])
			# ONLY FOR TEXT
			print("TESTING? " + self.datafilepath)
			datafile = open(self.datafilepath, "r")
			for line in datafile.xreadlines():
				self.openfile.writelines([line.replace('<','&lt;').replace('>','&gt;')]),
			datafile.close()
			self.openfile.writelines(["""</code></pre></td></tr></tbody></table><br />\n"""])
			self.openfile.close()
			
		if type == 'csv':
			# DON'T DO THE NEXT LINE FOR APPEND.  I THINK IT WILL CREATE AN EXTRA TABLE BUT DO THE H2 LINE
			self.openfile.writelines(["""<table class="nonparsed" border="0" cellpadding="0" cellspacing="0" width="100%"><tbody><tr><td> \n""",
				"""<h2 class="nonparsed_content"> <a href="file:///""" + self.datafilepath + """">""" + self.file + """</a> </h2></td></tr>"""])
			self.openfile.writelines(["""<table class="imagetable" border="0" cellpadding="0" cellspacing="0" width="100%"><tbody>\n"""])
			# ONLY FOR CSV
			#print("WHAT THE " + self.datafilepath)
			bomfile = open(self.datafilepath,'r').read(4)
			# debugit = open('C:\\Dumps\\BLAH-02-01-2012_1241\workfile', 'ab')
			# debugit.write(self.datafilepath + " \n")
			toggleVar =  self.check_bom(bomfile)
			if toggleVar:
				fi = codecs.open(self.datafilepath,'r', encoding='utf-16-le')
				datafile = iter(fi)
				datafile.next()
				# debugit.write("Found ToggleVar \n")
			else:
				print "not UTF-16 little endian"
				datafile = open(self.datafilepath, "r")
			count = 0
			datafile1 = csv.reader(datafile, dialect=csv.excel)
			for f in datafile1:
				line = f #.replace('\0', '').replace('<','&lt;').replace('>','&gt;').split(',')
				if count == 0:
					self.openfile.writelines(["""<tr>"""])
					for cell in line:
						cell = cell.replace('\0', '').replace('<','&lt;').replace('>','&gt;')
						self.openfile.writelines(["""<th>""" + cell + """</th>"""]),
					self.openfile.writelines(["""</tr>"""]),
					count =+ 1
				else:
					self.openfile.writelines(["""<tr>"""])
					for cell in line:
						cell = cell.replace('\0', '').replace('<','&lt;').replace('>','&gt;')
						self.openfile.writelines(["""<td>""" + cell + """</td>"""]),
						#if line[-1] == cell:
							#self.openfile.writelines(["""</tr>"""]),
					self.openfile.writelines(["""</tr>"""]),
					count =+ 1
			datafile.close()
			self.openfile.writelines(["""</td></tr></tbody></table><br />\n"""])
			self.openfile.close()

	# def isprintable(char):
		# return 0x20 <= char <= 0x7f
			
	def add_content(self):
		#print("Adding Contentttttttttttttttttttttttttttttttttttttttttttttttt")
		#self.fullreportfpath = self.filepath
		#file = self.file
		#name = self.name
		if self.file.find('.csv') != -1:
			type = 'csv'
		else:
			type = 'txt'
		if type == 'txt':
			self.openfile.writelines(["""<table class="nonparsed" border="0" cellpadding="0" cellspacing="0" width="100%"><tbody><tr><td> \n""",
			"""<h2 class="nonparsed_content"> <a href="file:///""" + self.datafilepath + """">""" + self.file + """</a> </h2></td></tr>"""])
			self.openfile.writelines(["""<table class="nonparsed_content" border="1" cellpadding="5" cellspacing="5" width="100%"><tbody><tr><td><pre><code>\n"""])
			# ONLY FOR TEXT
			print(self.datafilepath)
			datafile = open(self.datafilepath, "r")
			for line in datafile.xreadlines():
				self.openfile.writelines([line.replace('<','&lt;').replace('>','&gt;')]),
			datafile.close()
			self.openfile.writelines(["""</code></pre></td></tr></tbody></table><br />\n"""])
			self.openfile.close()
			
		if type == 'csv':
			self.openfile.writelines(["""<table class="nonparsed" border="0" cellpadding="0" cellspacing="0" width="100%"><tbody><tr><td> \n""",
			"""<h2 class="nonparsed_content"> <a href="file:///""" + self.datafilepath + """">""" + self.file + """</a> </h2></td></tr>"""])
			self.openfile.writelines(["""<table class="imagetable" border="0" cellpadding="0" cellspacing="0" width="100%"><tbody>\n"""])
			# ONLY FOR CSV
			print(self.datafilepath)
			bomfile = open(self.datafilepath,'r').read(4)
			# debugit = open('C:\\Dumps\\BLAH-02-01-2012_1241\workfile', 'ab')
			# debugit.write(self.datafilepath + " \n")
			toggleVar =  self.check_bom(bomfile)
			if toggleVar:
				fi = codecs.open(self.datafilepath,'r', encoding='utf-16-le')
				datafile = iter(fi)
				datafile.next()
			else:
				print "not UTF-16 little endian"
				datafile = open(self.datafilepath, "r")
			count = 0
			datafile1 = csv.reader(datafile, dialect=csv.excel)
			for f in datafile1:
				line = f #.replace('\0', '').replace('<','&lt;').replace('>','&gt;').split(',')
				if count == 0:
					self.openfile.writelines(["""<tr>"""])
					for cell in line:
						cell = cell.replace('\0', '').replace('<','&lt;').replace('>','&gt;')
						self.openfile.writelines(["""<th>""" + cell + """</th>"""]),
					self.openfile.writelines(["""</tr>"""]),
					count =+ 1
				else:
					self.openfile.writelines(["""<tr>"""])
					for cell in line:
						cell = cell.replace('\0', '').replace('<','&lt;').replace('>','&gt;')
						self.openfile.writelines(["""<td>""" + cell + """</td>"""]),
						#if line[-1] == cell:
							#self.openfile.writelines(["""</tr>"""]),
					self.openfile.writelines(["""</tr>"""]),
					count =+ 1
			datafile.close()
			self.openfile.writelines(["""</td></tr></tbody></table><br />\n"""])
			self.openfile.close()
			
		
	def finish_all(self):
		path = vars.outputdir + '\Report\\'
		for root, dir, files in os.walk(path):
			for file in files:
				self.filepath = root + "\\" + file
				size = os.stat(self.filepath).st_size
				print('Looking at ' + self.filepath + ", size is " + str(size))
				self.create_footer()
		# test = self.queue.pop(0)
		# print(test)
		# while self.queue != 0:
			# self.fullreportfpath = self.queue.pop(0)
			self.create_footer()
		
		
	def create_footer(self):
		print(self.filepath)
		#print(reportfile)
		self.openfile = open(self.filepath, "a")
		self.openfile.writelines(["""</tbody></table> \n""",
			"""<br /></td></tr></tbody></table> """,
			"""<hr /> \n""",
			"""<hr /> \n""",
			"""</div> \n""",
			"""</div> \n""",
			"""	<br /> \n""",
			"""</div> \n""",
			"""<div style="margin: 0pt; padding: 0pt; width: 100%; clear: both; background-color: transparent; position: relative;"> \n""",
			"""<div id="footer" style="width: 100%; margin-left: auto; margin-right: auto; height: 70px;"><br /> \n""",
			"""<div style="float:left;width:20%;text-align:left;padding-left:3px;padding-top:11px"><a href="http://www.theinterw3bs.com" target="_blank">TheInterW3bs.com</a> \n""",
			"""</div> \n""",
			"""<div style="word-spacing: 6px; font-size: 80%; padding-right: 12px; padding-top: 19px; float: right; width: 600px; text-align: right;"> \n""",
			"""		<a href="mailto:nick@theinterw3bs.com">REPORT ERROR</a> | \n""",
			"""		<a href="/index.htm" target="_top">HOME</a> | \n""",
			"""		<a href="#top" target="_top">TOP</a> | \n""",
			"""</div> \n""",
			"""<div style="padding-top: 13px; color: rgb(64, 64, 64); clear: both;"> \n""",
			"""		Disclaimer and stuff, blah, blah, blah - distributed under the Apache License 2.0.<br /> \n""",
			"""</div> \n""",
			"""</div> \n""",
			"""</div> \n""",
			"""</div> \n""",
			"""</body></html> \n""",
			])
		self.openfile.close()
		

#test = Reporter()
