import tkFileDialog, time, os, subprocess, glob, datetime, thread, fnmatch, os, sys
from Tkinter import *
from subprocess import *
#sys.path.append('files')
import kludge_vars as vars
import kludge_logger as log
import analyzer as analyze
import reporter as report
import comparer as comparer

class WhatThe():
	def __init__(self):
		"""Just A Class to kick off TKinter Class - no clue if this is correct"""
		self = self
		root = Tk()
		root.title("Kludge 4.1.2")
		Application(root)
		root.mainloop()

class Application(Frame):
	""" GUI application for Kludge"""
	def __init__(self, master):
		vars.KludgeVars()
		Frame.__init__(self, master)
		self.grid()
		self.create_widgets()

	def create_widgets(self):
		""" Create Kludge label widgets and all sorts of other GUI crap """
		Label(self,
			  text = "Kludge Data Collection Script\n"
			  ).grid(row = 0, column = 0, columnspan = 2, sticky = W)

		# option level label
		Label(self,
			  text = "Choose a Collection Level:"
			 ).grid(row = 1, column = 0, sticky = W)
		print("\n" + vars.timestmp)
		
		self.optlevel = IntVar()
		self.optlevel.set(2)
		# create option level radio buttons
		Radiobutton(self,
			text = "Simple Collection",
			variable = self.optlevel,
			value = 1
			).grid(row = 1, column = 1, sticky = W)

		# create option level radio buttons
		Radiobutton(self,
			text = "Timeline and Registry Collection  ",
			variable = self.optlevel,
			value = 2
			).grid(row = 1, column = 2, sticky = W)

		# create option level radio buttons
		Radiobutton(self,
			text = "Timeline, Registry, File Hashing Collection   ",
			variable = self.optlevel,
			value = 3
			).grid(row = 1, column = 3, sticky = W)
			
			
		# remote machine name and text entry
		Label(self,
			  text = "Remote Machine Name or IP: "
			  ).grid(row = 2, column = 0, sticky = W)
		remoteip = StringVar()
		remoteip.set("0.0.0.0")
		self.rmt_ip = Entry(self, textvariable=remoteip)
		self.rmt_ip.grid(row = 2, column = 1, sticky = W)
		
		
		# remote admin name and text entry
		Label(self,
			  text = "Admin Account Username: "
			  ).grid(row = 3, column = 0, sticky = W)
		adminname = StringVar()
		adminname.set(os.getenv('USERNAME'))
		self.admin_act = Entry(self, textvariable=adminname)
		self.admin_act.grid(row = 3, column = 1, sticky = W)
		
		# analyst name and text entry
		Label(self,
			  text = "Analyst Name: "
			  ).grid(row = 4, column = 0, sticky = W)
		yourname = StringVar()
		yourname.set(os.getenv('USERNAME'))
		self.anal_nam = Entry(self, textvariable=yourname)
		self.anal_nam.grid(row = 4, column = 1, sticky = W)
		
		# ticket number label and text
		Label(self,
			  text = "Ticket Number: "
			  ).grid(row = 5, column = 0, sticky = W)
		tix = StringVar()
		tix.set("86753o9")
		self.ticket_num = Entry(self, textvariable=tix)
		self.ticket_num.grid(row = 5, column = 1, sticky = W)
		
		
		# Dump Memory
		self.dump_mem = BooleanVar()
		Checkbutton(self,
					text = "Dump Memory",
					variable = self.dump_mem,
					command = self.update_button
					).grid(row = 6, column = 0, sticky = W)
					
					
		# Dump Memory
		self.collect_mail = BooleanVar()
		Checkbutton(self,
					text = "Collect Mail Files",
					variable = self.collect_mail,
					command = self.update_button
					).grid(row = 6, column = 1, sticky = W)
					
		# label for space
		Label(self, text = " ").grid(row = 7, column = 0, sticky = W)
		
		# Track incident
		self.record_inc = BooleanVar()
		Checkbutton(self,
					text = "Record this incident for tracking purposes",
					variable = self.record_inc,
					command = self.update_button
					).grid(row = 8, column = 0, sticky = W)
					
		
		# label for tracking button
		Label(self, text = "Select CSV file for incident tracking:  ").grid(row = 9, column = 0, sticky = W)
		
		# define tracking button
		self.csv_butt = Button(self, text='CSV File', command=self.ask_ir_track, state=DISABLED)
		self.csv_butt.grid(row = 9, column = 1, sticky = W)
		
		# label for space
		Label(self, text = " ").grid(row = 10, column = 0, sticky = W)
				
					
		# GPG Encryption
		self.use_gpg = BooleanVar()
		Checkbutton(self,
					text = "Use GPG Encryption (Private Key should already be imported)",
					variable = self.use_gpg,
					command = self.update_button
					).grid(row = 11, column = 0, sticky = W)
		
		# UID label and text
		Label(self,
			  text = "GPG UID:"
			  ).grid(row = 12, column = 0, sticky = W)
		self.gpg_uid = Entry(self)
		self.gpg_uid.grid(row = 12, column = 1, sticky = W)
		
		
		# label for gpg button
		Label(self, text = "Select Your GPG Public Key File:  ").grid(row = 13, column = 0, sticky = W)
		# define gpg button
		self.gpg_butt = Button(self, text='GPG Pub Key', command=self.ask_gpg_key, state=DISABLED)
		self.gpg_butt.grid(row = 13, column = 1, sticky = W)
		
#		Label(self, text = "\n\n\n").grid(row = 12, column = 2, sticky = W)
		
		
		# label for space
		Label(self, text = " ").grid(row = 14, column = 0, sticky = W)
		self.base_compare = BooleanVar()
		Checkbutton(self,
			text = "Baseline Comparison Checks",
			variable = self.base_compare,
			command = self.update_button
			).grid(row = 15, column = 0, sticky = W)

		Label(self, text = "Select Baseline Comparison Folder: ").grid(row = 16, column = 0, sticky = W)
		self.base_butt = Button(self, text='Baseline Report Folder', command=self.ask_base_dir, state=DISABLED)
		self.base_butt.grid(row = 16, column = 1, sticky = W)
		
		Label(self, text = " ").grid(row = 17, column = 0, sticky = W)
		self.vol_analysis = BooleanVar()
		Checkbutton(self,
			text = "Volatility Memory Analysis",
			variable = self.vol_analysis,
			command = self.update_button
			).grid(row = 18, column = 0, sticky = W)
			
		Label(self,
			text = "Select your Volatility Directory Location:     "
			).grid(row = 19, column = 0, sticky = W)
			
		# define report button
		self.vol_butt = Button(self, text='Volatility Directory', command=self.ask_vol_directory, state=DISABLED)
		self.vol_butt.grid(row = 19, column = 1, sticky = W)
		
		Label(self,
			text = " "
			).grid(row = 20, column = 0, sticky = W)
			
		self.rr_loc = BooleanVar()
		Checkbutton(self,
					text = "RegRipper Analysis (Collection Level 2 or 3)",
					variable = self.rr_loc,
					command = self.update_button
					).grid(row = 21, column = 0, sticky = W)

		Label(self, text = "Select RegRipper's rip.exe Location: ").grid(row = 22, column = 0, sticky = W)
		
		self.rr_butt = Button(self, text='RegRipper Location', command=self.ask_rr_rip, state=DISABLED)
		self.rr_butt.grid(row = 22, column = 1, sticky = W)
		
		Label(self,
			text = " "
			).grid(row = 23, column = 0, sticky = W)
		
		self.inline = BooleanVar()
		Checkbutton(self,
					text = "Detach Remote Process (Non-Interactive)",
					variable = self.inline,
					command = self.update_button
					).grid(row = 24, column = 0, sticky = W)
		
		Label(self,
			text = " "
			).grid(row = 25, column = 0, sticky = W)
		
		self.postreport = BooleanVar()
		Checkbutton(self,
					text = "Create Report from Previous collection (You must complete all information above)",
					variable = self.postreport,
					command = self.update_button
					).grid(row = 26, column = 0, sticky = W)
		
		Label(self, text = "Select the directory with collected zip files(c:\\windows\\temp): ").grid(row = 27, column = 0, sticky = W)
		
		self.postrep_butt = Button(self, text='Collected Zip File Directory', command=self.ask_postrep, state=DISABLED)
		self.postrep_butt.grid(row = 27, column = 1, sticky = W)
		
		Label(self,
			text = " "
			).grid(row = 28, column = 0, sticky = W)
			
			
		# label for report button
		Label(self, text = "Select a directory to store Report:  ").grid(row = 29, column = 0, sticky = W)
		
		# define report button
		Button(self, text='Report Directory',
		# command=self.askdirectory).grid(**button_opt)
		command=self.askdirectory).grid(row = 29, column = 1, sticky = W)
		
		Label(self,
			text = " "
			).grid(row = 30, column = 0, sticky = W)
		
			
		Button(self, text='Run new Kludge',
		command=self.run_kludge).grid(row = 31, column = 1, sticky = W)
		
		Button(self, text='Create Report from previous Kludge',
		command=self.run_postrep).grid(row = 31, column = 2, sticky = W)
		
		Label(self,
			text = " "
			).grid(row = 32, column = 0, sticky = W)
		
	def update_button(self):
		"""Changes Button State to Enabled if Compare Function is True"""
		if self.base_compare.get():
			self.base_butt['state'] = NORMAL
			vars.basecomp_run = "yes"
		else:
			self.base_butt['state'] = DISABLED
			vars.basecomp_run = "no"
		if self.use_gpg.get():
			self.gpg_butt['state'] = NORMAL
			vars.gpg_enc = "yes"
		else:
			self.gpg_butt['state'] = DISABLED
			vars.gpg_enc = "no"
		if self.record_inc.get():
			self.csv_butt['state'] = NORMAL
			vars.ticket_rec = "yes"
		else:
			self.csv_butt['state'] = DISABLED
			vars.ticket_rec = "no"
		if self.rr_loc.get():
			self.rr_butt['state'] = NORMAL
			vars.rr_run = "yes"
		else:
			self.rr_butt['state'] = DISABLED
			vars.rr_run = "no"
		if self.vol_analysis.get():
			self.vol_butt['state'] = NORMAL
			vars.vol_run = "yes"
		else:
			self.vol_butt['state'] = DISABLED
			vars.vol_run = "no"
		if self.dump_mem.get():
			vars.dumpm = "yes"
		else:
			vars.dumpm = "no"
		if self.collect_mail.get():
			vars.mailgrab = "yes"
		else:
			vars.mailgrab = "no"
		if self.inline.get():
			vars.detach = "yes"
		else:
			vars.detach = "no"
		if self.postreport.get():
			self.postrep_butt['state'] = NORMAL
			vars.postrep = "yes"
		else:
			self.postrep_butt['state'] = DISABLED
			vars.postrep = "no"
		
		# else:
			# print ('Nothing Selected')
			
	def askdirectory(self):
		"""Selects Report Storage Location and prints it"""
		report_dir_tmp = tkFileDialog.askdirectory(title="Please Select a Folder to Store Report", initialdir = "C:\\", mustexist = "False")
		vars.report_dir = report_dir_tmp.replace("/","\\")
		print("Report Directory " + vars.report_dir)
		
		
	def ask_vol_directory(self):
		"""Selects Volatility's Directory and prints it"""
		vol_dirtmp = tkFileDialog.askdirectory(title="Please Select Volatility's vol.py's Location", initialdir = "C:\\", mustexist = "False")
		vars.vol_dir = vol_dirtmp.replace("/","\\")
		print ("Volatility Directory " + vars.vol_dir)
		
		
	def ask_base_dir(self):
		"""Selects Baseline Report Folder and Prints it"""
		vars.base_dir = tkFileDialog.askdirectory(title="Please Select Baseline Report Directory", initialdir = "C:\\", mustexist = "False")
		print ("Baseline Directory " + vars.base_dir)
		
	def ask_gpg_key(self):
		"""Selects GPG File and Prints it"""
		gpg_key_tmp = tkFileDialog.askopenfilename(title="Please Select Your GPG Key", initialdir = "C:\\")
		vars.gpg_key = gpg_key_tmp.replace("/","\\")
		print ("GPG Pub Key " + vars.gpg_key)
		
	def ask_ir_track(self):
		"""Selects CSV Tracking"""
		ir_trk_tmp = tkFileDialog.askopenfilename(title="Please Select a CSV File to Record Incident", initialdir = "C:\\")
		vars.ir_trk = ir_trk_tmp.replace("/","\\")
		print ("Incident CSV File " + vars.ir_trk)
		
	def ask_postrep(self):
		"""Selects Report Directory for a post report and prints it"""
		postrep_dirtmp = tkFileDialog.askdirectory(title="Please Select the Location of the collected zip files", initialdir = "C:\\Windows\\Temp", mustexist = "False")
		vars.tmp_trgt_dir = postrep_dirtmp.replace("/","\\")
		print ("Directory containing previously collected zip files " + vars.tmp_trgt_dir)
	
	def run_postrep(self):
		"""blah blah"""
		vars.cmpnam = str(self.rmt_ip.get()) + "-" + str(vars.timestmp)
		vars.cname = str(self.rmt_ip.get())
		vars.outputdir = vars.report_dir + "\\" + str(vars.cmpnam)
		self.extract_it()
		
		
	def ask_rr_rip(self):
		"""Selects RegRipper rip.exe location"""
		rip_tmp = tkFileDialog.askopenfilename(title="Please Select the RegRipper rip.exe", initialdir = "C:\\")
		vars.riploc = rip_tmp.replace("/","\\")
		print ("RegRipper rip.exe location " + vars.riploc)
		
	def run_kludge(self):
		"""Execute the Script, check if memory dump is done and check if remote script is done"""
		vars.rmt_ip = self.rmt_ip.get()
		vars.admin_act = self.admin_act.get()
		vars.anal_nam = self.anal_nam.get()
		vars.ticket_num = self.ticket_num.get()
		vars.optlevel = self.optlevel.get()
		if vars.optlevel == 1:
			print("\n\nRunning Simple Collection Level\n")
		elif vars.optlevel == 2:
			print("\n\nRunning Detailed Collection Level including Timeline and Registry collection\n")
		elif vars.optlevel == 3:
			print("\n\nRunning Detailed Collection Level including Timeline, Registry, and File Hashing collection\n")
		print("\t\tRemote Target is " + vars.rmt_ip)
		print("\t\tUsing Admin Account -- " + vars.admin_act)
		print("\t\tRecord Ticket Incident " + vars.ticket_rec)
		if vars.ticket_rec == "yes":
			print("\t\tRecord Incident to " + vars.ir_trk)
			print("\t\tAssociated Ticket Number " + vars.ticket_num)
		print("\t\tDump Memory Option == " + vars.dumpm)
		print("\t\tCollect Mail Files Option == " + vars.mailgrab)
		print("\t\tGPG Encryption Option == " + vars.gpg_enc)
		print("\t\tBase Comparison Option == " + vars.basecomp_run)
		print("\t\tVolatility Option == " + vars.vol_run)
		print("\t\tRegRipper Option == " + vars.rr_run)
		if vars.basecomp_run == "yes":
			print("\t\tBaseline Comparison Directory is " + vars.base_dir)
		print("\t\tDetach Remote Process " + vars.detach)
		print("\t\tReport Directory is " + vars.report_dir)
		print("\t\tWill prompt for password multiple times\n\n")
		#time.sleep(5)
		vars.tmp_trgt_dir = "c:\\windows\\temp\\" + vars.rmt_ip + "-temp"+ "-" + str(vars.timestmp)
		call("mkdir " + vars.tmp_trgt_dir, shell=True)
		call("net use \\\\" + vars.rmt_ip + "\\IPC$ /u:" +  vars.admin_act, shell=True)
		call("xcopy " + " files\\kludge.zip" + " \\\\" + vars.rmt_ip + "\\c$\\Windows\\Temp\\ /Y /K", shell=True)
		call("xcopy " + " files\\7za.exe" + " \\\\" + vars.rmt_ip + "\\c$\\Windows\\Temp\\  /Y /K", shell=True)
		print("\nExtracting Script")
		call("wmic" + " /node:" + vars.rmt_ip + " /user:" + vars.admin_act +  " process call create \"C:\\Windows\\Temp\\7za.exe x c:\\Windows\\Temp\\kludge.zip -oC:\\Windows\\Temp\\analysis\\\"", shell=True)
		# print("\nCollecting Remote Hostname")
		# call("wmic" + " /node:" + vars.rmt_ip + " /user:" + vars.admin_act +  " process call create \"cmd.exe /c echo %COMPUTERNAME%> c:\\windows\\temp\\analysis\\computername.txt\"", shell=True)
		print("\Determining Windows version")
		call("systeminfo /s " + vars.rmt_ip + " /u " + vars.admin_act + " >" + vars.tmp_trgt_dir + "\\systeminfo.txt", shell=True)
		call("files\\src\\grep.exe \"^OS Version\" " + vars.tmp_trgt_dir + "\\systeminfo.txt >" + vars.tmp_trgt_dir + "\\" + "WinVer.txt", shell=True)
		call("files\\src\\grep.exe -i \"System Type:\" " + vars.tmp_trgt_dir + "\\systeminfo.txt >>" + vars.tmp_trgt_dir + "\\" + "WinVer.txt", shell=True)
		checkverf = open(vars.tmp_trgt_dir + "\\WinVer.txt", 'r')
		print(checkverf)
		for line in checkverf.xreadlines():
			print("Windows version " + line)
			if "6.1" in line:
				vars.winver = "win7"
			elif "5.1" in line:
				vars.winver = "winxp"
			elif "5.2" in line:
				vars.winver = "winxp"
			elif "6.0" in line:
				vars.winver = "win7"
			elif "5.0" in line:
				vars.winver = "winxp"
			elif "x86-based" in line.lower():
				vars.proctype = "x86"
			elif "x64-based" in line.lower():
				vars.proctype = "x64"
		if vars.winver == "win7" and vars.proctype == "x86":
			self.kludge = "kludge-win7.bat"
		elif vars.winver == "win7" and vars.proctype == "x64":
			self.kludge = "kludge-win7x64.bat"
		elif vars.winver == "winxp" and vars.proctype == "x86":
			self.kludge = "kludge-winxp.bat"
		else:
			self.kludge = "kludge-win7.bat"
		checkverf.close()
		print("\n\nWindows Version is " + vars.winver + " " + vars.proctype)
		print("\n\nRunning " + self.kludge + "\n\n")
		# if vars.gpg_enc:
		if vars.gpg_key != None:
			g=open(vars.tmp_trgt_dir + "\\uid.txt", 'w')
			g.write(str(self.gpg_uid.get()) + '\n')
			g.close()
			call("xcopy " + vars.tmp_trgt_dir + "\\uid.txt \\\\" + vars.rmt_ip + "\\c$\\Windows\\Temp\\analysis\\ /Y /K", shell=True)
			# if vars.gpg_key != None:
			call("copy /Y /V " + vars.gpg_key + " \\\\" + vars.rmt_ip + "\\c$\\Windows\\Temp\\analysis\\pubkey.txt", shell=True)
		else:
			print("GPG Encryption Not Used")
		if vars.winver == "win7":
			print("Looking for LogParser files at C:\Program Files\Log Parser 2.2")
			call("xcopy \"C:\\Program Files\\Log Parser 2.2\\LogParser.dll\" \\\\" + vars.rmt_ip + "\\c$\\Windows\\Temp\\analysis\\ /Y /K", shell=True)
			call("xcopy \"C:\\Program Files\\Log Parser 2.2\\LogParser.exe\" \\\\" + vars.rmt_ip + "\\c$\\Windows\\Temp\\analysis\\ /Y /K", shell=True)
			
		# WMIC Crud - Starts WMIC Script
		"""TRY starting WMIC Script in a seperate thread to possibly avoid wmic failures on the remote"""
		#thread.start_new_thread(self.run_wmics,())
		try:
			self.run_wmics()
			self.namegen()
			# return 0
		except:
			# log.logger.debug
			# return 1
			pass
		
		# Start separate memory check thread
		if vars.dumpm == "yes":
			thread.start_new_thread(self.memory_done,())
		
		#thread.start_new_thread(self.check_done,())
		if vars.detach == "yes":
			call("files\\psexec.exe -d \\\\" + vars.rmt_ip +  " -s cmd.exe /c \"cd c:\\Windows\\Temp\\analysis && C:\\Windows\\Temp\\analysis\\" + self.kludge + " " + str(vars.optlevel) + " " + vars.gpg_enc + " " +  vars.dumpm + " " + vars.mailgrab + "\"", shell=True)
		else:
			print self.kludge
			call("files\\psexec.exe \\\\" + vars.rmt_ip +  " -s cmd.exe /c \"cd c:\\Windows\\Temp\\analysis && C:\\Windows\\Temp\\analysis\\" + self.kludge + " " + str(vars.optlevel) + " " + vars.gpg_enc + " " +  vars.dumpm + " " + vars.mailgrab + "\"", shell=True)
		
		#Copy systeminfo over to remote
		call("xcopy " + vars.tmp_trgt_dir + "\\systeminfo.txt \\\\" + vars.rmt_ip + "\\c$\\Windows\\Temp\\analysis\\SysInfo\\ /Y /K", shell=True)
		
		# Run the function to that checks if the remote script is complete
		self.check_done()
		
	def run_wmics(self):
		"""Runs wmic script cause psexec is causing issues with wmic output and namespace errors - fix me one day"""
		print("\n\nRunning remote wmic collection script")
		call("wmic /node:" + vars.rmt_ip + " /user:" + vars.admin_act +  " process call create \"cmd.exe /c cd c:\\Windows\\Temp\\analysis && C:\\Windows\\Temp\\analysis\\kludge-wmics.bat\"", shell=True)

	def namegen(self):
		"""Create ComputerName Variable, OutputDir"""
		if vars.postrep == "yes":
			vars.outputdir = vars.report_dir + "\\" + str(vars.cmpnam)
		else:
			f = open(vars.tmp_trgt_dir + "\\systeminfo.txt", 'r')
			for i, line in enumerate(f):
				if i == 1:
					row = line.split()
					vars.cmpnam = str(row[2].replace("\n","") + "-" + str(vars.timestmp))
					vars.cname = str(row[2].replace("\n",""))
					vars.outputdir = vars.report_dir + "\\" + str(vars.cmpnam)
					print row[2]
				elif i > 1:
					break
			f.close()

		
	def memory_done(self):
		"""If Memory dumping was enabled this will check every 10 seconds to see if the file is done and then transfer it over.  It checks if GPG was enabled"""
		print ("Running Memory Check Done")
		#mem_file = "\\\\" + vars.rmt_ip + "\\c$\\Windows\\Temp\\analysis\\mem-done.txt"
		self.mem_file = "\\\\" + vars.rmt_ip + "\\c$\\Windows\\Temp\\physmem-" + vars.cname + ".dump"
		#os.path.getsize(self.mem_file) > 100:
		while os.path.exists(self.mem_file) == False:
			print("Memory Dump not done")
			time.sleep(10)
		else:
			self.copymem()
	
	def copymem(self):
		"""Copies Memory if size is larger than 0 - when memory is dumping the file is 0kb until finished, or so I think"""
		while os.path.getsize(self.mem_file) < 100:
			print("Memory Dump not done")
			time.sleep(10)
		else:
			print("Copying Memory Dump from Remote Machine")
			if vars.gpg_enc == "yes":
				call("mkdir " +  vars.tmp_trgt_dir + "\\gpg", shell=True)
				call("xcopy " + " \\\\" + vars.rmt_ip + "\\c$\\Windows\\Temp\\physmem*.* " +  vars.tmp_trgt_dir + "\\gpg\\ /Y /K", shell=True)
				# time.sleep(10)
			else:
				call("xcopy " + " \\\\" + vars.rmt_ip + "\\c$\\Windows\\Temp\\physmem*.* " +  vars.tmp_trgt_dir + "\\ /Y /K", shell=True)
			call("del \\\\" + vars.rmt_ip + self.mem_file.replace("/","\\"), shell=True)
			call("del \\\\" + vars.rmt_ip + "\\c$\\Windows\\Temp\\physmem*.*", shell=True)
			vars.memdone = "pork fried rice"
			
	def check_done(self):
		"""Checking for the existence of a done.txt on the remote machine.  If file exists then start the copying"""
		print ("Checking if Remote Collection is complete")
		fin_file = "\\\\" + vars.rmt_ip + "\\c$\\Windows\\Temp\\analysis\\done.txt"
		while os.path.exists(fin_file) == False:
			time.sleep(10)
		else:
			print("Information Gathering Complete")
			print("Transferring CollectedData Files")
			if vars.gpg_enc == "yes":
				call("mkdir " +  vars.tmp_trgt_dir + "\\gpg", shell=True)
				call("xcopy " + " \\\\" + vars.rmt_ip + "\\c$\\Windows\\Temp\\CollectedData*.gpg " +  vars.tmp_trgt_dir + "\\gpg\\ /Y /K", shell=True)
			else:
				call("xcopy " + " \\\\" + vars.rmt_ip + "\\c$\\Windows\\Temp\\CollectedData*.* " +  vars.tmp_trgt_dir + " /Y /K", shell=True)
			print("Transfer Complete")
			thread.start_new_thread(self.clean_up,())
			
	def clean_up(self):
		"""Remove itself from the remote machine"""
		print("Cleaning up Temporary Files on Remote and Local Machine")
		call("del \\\\" + vars.rmt_ip + "\\c$\\Windows\\Temp\\kludge.zip", shell=True)
		call("del \\\\" + vars.rmt_ip + "\\c$\\Windows\\Temp\\7za.exe", shell=True)
		#call("xcopy " + " \\\\" + vars.rmt_ip + "\\c$\\Windows\\Temp\\analysis\\SysInfo\\computername.txt " +  vars.tmp_trgt_dir + " /Y /K", shell=True)
		
		"""If Memory was selected and memdone var not set don't continue"""
		if vars.dumpm == "yes":
			while vars.memdone == None:
				print("Memory Copying not done - still transferring memory files")
				time.sleep(10)
			else:
				call("del \\\\" + vars.rmt_ip + "\\c$\\Windows\\Temp\\analysis\\SysInfo\\computername.txt", shell=True)
				call("rmdir /s /q \\\\" + vars.rmt_ip + "\\c$\\Windows\\Temp\\analysis", shell=True)
				call("del \\\\" + vars.rmt_ip + "\\c$\\Windows\\Temp\\CollectedData-*.*", shell=True)
				self.extract_it()
		else:
			call("del \\\\" + vars.rmt_ip + "\\c$\\Windows\\Temp\\analysis\\SysInfo\\computername.txt", shell=True)
			call("rmdir /s /q \\\\" + vars.rmt_ip + "\\c$\\Windows\\Temp\\analysis", shell=True)
			call("del \\\\" + vars.rmt_ip + "\\c$\\Windows\\Temp\\CollectedData-*.*", shell=True)
			self.extract_it()
		
	def extract_it(self):
		"""Extract files and unencrypt if need be"""
		print("Extracting Files - Unzipping Errors can usually be ignored")
		if vars.gpg_enc == "yes":
			print("Decrypting CollectedData Files")
			vars.gpgNames = glob.glob(vars.tmp_trgt_dir + "\\gpg\\*.gpg")
			for xyz in vars.gpgNames:
				call("files\\src\\gpg.exe --output " + xyz.replace(".gpg","").replace("\\gpg","") + " -d " + xyz, shell=True)
		
		"""Iterate thru all files named CollectedData- and unzip --- 002, 003, 004 and so on will error and be ignored"""
		self.fileNames = glob.glob(vars.tmp_trgt_dir + "\\CollectedData-*.*")
		for item in self.fileNames:
			print(vars.outputdir)
			print("Unzipping " + item)
			print("files\\7za.exe x \"" + str(item) + "\" -o" + vars.outputdir + "\\")
			call("files\\7za.exe x \"" + str(item) + "\" -o" + vars.outputdir + "\\", shell=True)
		
		if vars.ticket_rec == "yes":
			# raw_input("Press Enter to continue...")
			print("Recording Incident Ticket Number")
			print(vars.tmp_trgt_dir + "\\tickets.csv")
			# raw_input("Press Enter to continue...")
			t=open(vars.tmp_trgt_dir + "\\tickets.csv", 'w')
			t.write("ComputerName,Date,Ticket Number,Analyst\n")
			#raw_input("Press Enter to continue...")
			tick=open(vars.ir_trk, 'r')
			for tix in tick:
				if vars.cname in tix:
					t.writelines(str(tix))
			tick.close()
			t.close()
			call("echo " + str(vars.cname) + "," + str(vars.justdate) + "," + str(vars.ticket_num) + "," + str(vars.anal_nam)  + " >> " + str(vars.ir_trk), shell=True)
			print("echo " + str(vars.cname) + "," + str(vars.justdate) + "," + str(vars.ticket_num) + "," + str(vars.anal_nam)  + " >> " + str(vars.ir_trk))
			# raw_input("Press Enter to continue...")
		self.finish_up()
			
		
	def finish_up(self):
		"""Move the last bit of collected data and then start the Analyzer, Comparer and Reporter"""
		print("Collection is Complete")
		call("move " + vars.tmp_trgt_dir + "\\CollectedData*.* " + vars.outputdir + "\\", shell=True)
		#call("move " + vars.tmp_trgt_dir + "\\systeminfo.txt " + vars.outputdir + "\\SysInfo\\", shell=True)
		if vars.dumpm == "yes":
			call("mkdir " + vars.outputdir + "\\MemInfo\\", shell=True)
			call("move " + vars.tmp_trgt_dir + "\\physmem*.* " + vars.outputdir + "\\MemInfo\\", shell=True)
		if vars.gpg_enc == "yes":
			call("move " + vars.tmp_trgt_dir + "\\gpg\\CollectedData*.* " + vars.outputdir + "\\", shell=True)
		analyze.Analyzer()
		if vars.basecomp_run == "yes":
			comparer.Comparer()
		report.Reporter()
		self.all_done()
		
	def all_done(self):
		print("Report Complete")
		print("Deleting Local Temp Files - " + vars.tmp_trgt_dir)
		call("rmdir /s /q " + vars.tmp_trgt_dir, shell=True)
		print("Look in " + vars.outputdir + "\Report for the parsed data")
		sys.exit()
		
		
		
		
		
		
# root = Tk()
# root.title("Kludge 4.0.0")
# app = Application(root)
# root.mainloop()
