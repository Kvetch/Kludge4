import tkFileDialog, time, os, subprocess, glob, datetime, thread, fnmatch, csv, sys
from Tkinter import *
from subprocess import *
#sys.path.append('files')
import kludge_vars as vars
import kludge_logger as log

class Analyzer(object):
	""" Analyzer for Kludge"""
	def __init__(self):
		self.analyze_it()
		
		
	def analyze_it(self):
		"""Parses the data first with RegRipper, then with Volatility, the Timeline and finally move tickets.txt file into position for parsing"""
		try:
			if vars.rr_run == "yes":
				print("Starting RegRipper")
				#thread.start_new_thread(self.regrip_analyze,())
				self.regrip_analyze()
				# return 0
		except:
			# log.logger.debug
			pass

		# Run Volatility
		try:
			if vars.vol_run == "yes":
				print("Starting Volatility Analysis")
				#thread.start_new_thread(self.mem_analyze,())
				self.mem_analyze()
		except:
			# log.logger.debug
			pass

		# If Option Level was great or equal to 2 run Event Parser, Reg Parser and TLN Parser	
		try:	
			if vars.optlevel >= 2:
				self.evtparser()
				self.regparser()
				self.tlnparser()
		except:
			# log.logger.debug
			pass

			
		# If Ticket recording was enabled	
		try:	
			if vars.ticket_rec == "yes":
				print("move " + vars.tmp_trgt_dir + "\\tickets.csv " + vars.outputdir + "\\SysInfo\\")
				call("move " + vars.tmp_trgt_dir + "\\tickets.csv " + vars.outputdir + "\\SysInfo\\", shell=True)
				# raw_input("Press Enter to continue...")
			print("Do some fancy schmancy stuff here\n\n")
		except:
			# log.logger.debug
			pass

			
			
	def regrip_analyze(self):
		""" RegRipper Instructions broken down by ntuser, sam, security, software and system"""
		self.regrip_dir = vars.outputdir + "\\Registry\\RegRipper\\"
		print("Creating Directory " +  self.regrip_dir)
		call("mkdir " +  self.regrip_dir, shell=True)
		for root, dir, files in os.walk(vars.outputdir + '\Registry'):
			for file in files:
				print('Indexing ' + root + "\\" + file + '\n')
				if fnmatch.fnmatch(file, 'ntuser.dat'):
					temp_root = root.split('\\')
					root_len = len(temp_root)
					self.ntuserpath = self.regrip_dir + temp_root[root_len -1] + "-ntuser-info"
					#ntuser_name = temp_root[root_len -1]
					call("mkdir " + self.ntuserpath , shell=True)
					print("Creating Directory " +  self.ntuserpath)
					ntuser_matchdir = os.path.join(root, file)
					self.rip_ntuser(ntuser_matchdir)
				elif fnmatch.fnmatch(file, 'sam'):
					sam_matchdir = os.path.join(root, file)
					self.sampath = self.regrip_dir + "\\SYSTEM-info"
					call("mkdir " + self.sampath , shell=True)
					self.rip_sam(sam_matchdir)
				elif fnmatch.fnmatch(file, 'security'):
					security_matchdir = os.path.join(root, file)
					self.secpath = self.regrip_dir + "\\SECURITY-info"
					call("mkdir " + self.secpath , shell=True)
					self.rip_security(security_matchdir)
				elif fnmatch.fnmatch(file, 'software'):
					software_matchdir = os.path.join(root, file)
					self.softpath = self.regrip_dir + "\\SOFTWARE-info"
					call("mkdir " + self.softpath , shell=True)
					self.rip_software(software_matchdir)
				elif fnmatch.fnmatch(file, 'system'):
					system_matchdir = os.path.join(root, file)
					self.syspath = self.regrip_dir + "\\SYSTEM-info"
					call("mkdir " + self.syspath , shell=True)
					self.rip_system(system_matchdir)
	
	def rip_ntuser(self,ntuser_matchdir):
		"""NTUSER Ripping"""
		ntuser_matchdir = ntuser_matchdir
		print(ntuser_matchdir)
		#temp_ntuser_dir = temp_ntuser_dir
		#print(temp_ntuser_dir)
		print("Running RegRipper plugin ---> acmru against " + ntuser_matchdir + "\n")
		call(vars.riploc + " -r " + ntuser_matchdir + " -p " + "acmru" + " >> " + self.ntuserpath + "\\acmru.txt", shell=True)
		print("Running RegRipper plugin ---> adoberdr against " + ntuser_matchdir + "\n")
		call(vars.riploc + " -r " + ntuser_matchdir + " -p " + "adoberdr" + " >> " + self.ntuserpath + "\\adoberdr.txt", shell=True)
		print("Running RegRipper plugin ---> aim against " + ntuser_matchdir + "\n")
		call(vars.riploc + " -r " + ntuser_matchdir + " -p " + "aim" + " >> " + self.ntuserpath + "\\aim.txt", shell=True)
		print("Running RegRipper plugin ---> aports against " + ntuser_matchdir + "\n")
		call(vars.riploc + " -r " + ntuser_matchdir + " -p " + "aports" + " >> " + self.ntuserpath + "\\aports.txt", shell=True)
		print("Running RegRipper plugin ---> appcompatflags against " + ntuser_matchdir + "\n")
		call(vars.riploc + " -r " + ntuser_matchdir + " -p " + "appcompatflags" + " >> " + self.ntuserpath + "\\appcompatflags.txt", shell=True)
		print("Running RegRipper plugin ---> applets against " + ntuser_matchdir + "\n")
		call(vars.riploc + " -r " + ntuser_matchdir + " -p " + "applets" + " >> " + self.ntuserpath + "\\applets.txt", shell=True)
		print("Running RegRipper plugin ---> arpcache against " + ntuser_matchdir + "\n")
		call(vars.riploc + " -r " + ntuser_matchdir + " -p " + "arpcache" + " >> " + self.ntuserpath + "\\arpcache.txt", shell=True)
		print("Running RegRipper plugin ---> autoendtasks against " + ntuser_matchdir + "\n")
		call(vars.riploc + " -r " + ntuser_matchdir + " -p " + "autoendtasks" + " >> " + self.ntuserpath + "\\autoendtasks.txt", shell=True)
		print("Running RegRipper plugin ---> autorun against " + ntuser_matchdir + "\n")
		call(vars.riploc + " -r " + ntuser_matchdir + " -p " + "autorun" + " >> " + self.ntuserpath + "\\autorun.txt", shell=True)
		print("Running RegRipper plugin ---> bagtest against " + ntuser_matchdir + "\n")
		call(vars.riploc + " -r " + ntuser_matchdir + " -p " + "bagtest" + " >> " + self.ntuserpath + "\\bagtest.txt", shell=True)
		print("Running RegRipper plugin ---> bagtest2 against " + ntuser_matchdir + "\n")
		call(vars.riploc + " -r " + ntuser_matchdir + " -p " + "bagtest2" + " >> " + self.ntuserpath + "\\bagtest2.txt", shell=True)
		print("Running RegRipper plugin ---> bitbucket_user against " + ntuser_matchdir + "\n")
		call(vars.riploc + " -r " + ntuser_matchdir + " -p " + "bitbucket_user" + " >> " + self.ntuserpath + "\\bitbucket_user.txt", shell=True)
		print("Running RegRipper plugin ---> brisv against " + ntuser_matchdir + "\n")
		call(vars.riploc + " -r " + ntuser_matchdir + " -p " + "brisv" + " >> " + self.ntuserpath + "\\brisv.txt", shell=True)
		print("Running RegRipper plugin ---> cain against " + ntuser_matchdir + "\n")
		call(vars.riploc + " -r " + ntuser_matchdir + " -p " + "cain" + " >> " + self.ntuserpath + "\\cain.txt", shell=True)
		print("Running RegRipper plugin ---> clampitm against " + ntuser_matchdir + "\n")
		call(vars.riploc + " -r " + ntuser_matchdir + " -p " + "clampitm" + " >> " + self.ntuserpath + "\\clampitm.txt", shell=True)
		print("Running RegRipper plugin ---> comdlg32 against " + ntuser_matchdir + "\n")
		call(vars.riploc + " -r " + ntuser_matchdir + " -p " + "comdlg32" + " >> " + self.ntuserpath + "\\comdlg32.txt", shell=True)
		print("Running RegRipper plugin ---> comdlg32a against " + ntuser_matchdir + "\n")
		call(vars.riploc + " -r " + ntuser_matchdir + " -p " + "comdlg32a" + " >> " + self.ntuserpath + "\\comdlg32a.txt", shell=True)
		print("Running RegRipper plugin ---> compdesc against " + ntuser_matchdir + "\n")
		call(vars.riploc + " -r " + ntuser_matchdir + " -p " + "compdesc" + " >> " + self.ntuserpath + "\\compdesc.txt", shell=True)
		print("Running RegRipper plugin ---> controlpanel against " + ntuser_matchdir + "\n")
		call(vars.riploc + " -r " + ntuser_matchdir + " -p " + "controlpanel" + " >> " + self.ntuserpath + "\\controlpanel.txt", shell=True)
		print("Running RegRipper plugin ---> cpldontload against " + ntuser_matchdir + "\n")
		call(vars.riploc + " -r " + ntuser_matchdir + " -p " + "cpldontload" + " >> " + self.ntuserpath + "\\cpldontload.txt", shell=True)
		print("Running RegRipper plugin ---> decaf against " + ntuser_matchdir + "\n")
		call(vars.riploc + " -r " + ntuser_matchdir + " -p " + "decaf" + " >> " + self.ntuserpath + "\\decaf.txt", shell=True)
		print("Running RegRipper plugin ---> dependency_walker against " + ntuser_matchdir + "\n")
		call(vars.riploc + " -r " + ntuser_matchdir + " -p " + "dependency_walker" + " >> " + self.ntuserpath + "\\dependency_walker.txt", shell=True)
		print("Running RegRipper plugin ---> domains against " + ntuser_matchdir + "\n")
		call(vars.riploc + " -r " + ntuser_matchdir + " -p " + "domains" + " >> " + self.ntuserpath + "\\domains.txt", shell=True)
		print("Running RegRipper plugin ---> environment against " + ntuser_matchdir + "\n")
		call(vars.riploc + " -r " + ntuser_matchdir + " -p " + "environment" + " >> " + self.ntuserpath + "\\environment.txt", shell=True)
		print("Running RegRipper plugin ---> fileexts against " + ntuser_matchdir + "\n")
		call(vars.riploc + " -r " + ntuser_matchdir + " -p " + "fileexts" + " >> " + self.ntuserpath + "\\fileexts.txt", shell=True)
		print("Running RegRipper plugin ---> gthist against " + ntuser_matchdir + "\n")
		call(vars.riploc + " -r " + ntuser_matchdir + " -p " + "gthist" + " >> " + self.ntuserpath + "\\gthist.txt", shell=True)
		print("Running RegRipper plugin ---> gtwhitelist against " + ntuser_matchdir + "\n")
		call(vars.riploc + " -r " + ntuser_matchdir + " -p " + "gtwhitelist" + " >> " + self.ntuserpath + "\\gtwhitelist.txt", shell=True)
		print("Running RegRipper plugin ---> haven_and_hearth against " + ntuser_matchdir + "\n")
		call(vars.riploc + " -r " + ntuser_matchdir + " -p " + "haven_and_hearth" + " >> " + self.ntuserpath + "\\haven_and_hearth.txt", shell=True)
		print("Running RegRipper plugin ---> ie_main against " + ntuser_matchdir + "\n")
		call(vars.riploc + " -r " + ntuser_matchdir + " -p " + "ie_main" + " >> " + self.ntuserpath + "\\ie_main.txt", shell=True)
		print("Running RegRipper plugin ---> ie_settings against " + ntuser_matchdir + "\n")
		call(vars.riploc + " -r " + ntuser_matchdir + " -p " + "ie_settings" + " >> " + self.ntuserpath + "\\ie_settings.txt", shell=True)
		print("Running RegRipper plugin ---> iexplore against " + ntuser_matchdir + "\n")
		call(vars.riploc + " -r " + ntuser_matchdir + " -p " + "iexplore" + " >> " + self.ntuserpath + "\\iexplore.txt", shell=True)
		print("Running RegRipper plugin ---> listsoft against " + ntuser_matchdir + "\n")
		call(vars.riploc + " -r " + ntuser_matchdir + " -p " + "listsoft" + " >> " + self.ntuserpath + "\\listsoft.txt", shell=True)
		print("Running RegRipper plugin ---> liveContactsGUID against " + ntuser_matchdir + "\n")
		call(vars.riploc + " -r " + ntuser_matchdir + " -p " + "liveContactsGUID" + " >> " + self.ntuserpath + "\\liveContactsGUID.txt", shell=True)
		print("Running RegRipper plugin ---> load against " + ntuser_matchdir + "\n")
		call(vars.riploc + " -r " + ntuser_matchdir + " -p " + "load" + " >> " + self.ntuserpath + "\\load.txt", shell=True)
		print("Running RegRipper plugin ---> logon_xp_run against " + ntuser_matchdir + "\n")
		call(vars.riploc + " -r " + ntuser_matchdir + " -p " + "logon_xp_run" + " >> " + self.ntuserpath + "\\logon_xp_run.txt", shell=True)
		print("Running RegRipper plugin ---> logonusername against " + ntuser_matchdir + "\n")
		call(vars.riploc + " -r " + ntuser_matchdir + " -p " + "logonusername" + " >> " + self.ntuserpath + "\\logonusername.txt", shell=True)
		print("Running RegRipper plugin ---> mmc against " + ntuser_matchdir + "\n")
		call(vars.riploc + " -r " + ntuser_matchdir + " -p " + "mmc" + " >> " + self.ntuserpath + "\\mmc.txt", shell=True)
		print("Running RegRipper plugin ---> mndmru against " + ntuser_matchdir + "\n")
		call(vars.riploc + " -r " + ntuser_matchdir + " -p " + "mndmru" + " >> " + self.ntuserpath + "\\mndmru.txt", shell=True)
		print("Running RegRipper plugin ---> mp2 against " + ntuser_matchdir + "\n")
		call(vars.riploc + " -r " + ntuser_matchdir + " -p " + "mp2" + " >> " + self.ntuserpath + "\\mp2.txt", shell=True)
		print("Running RegRipper plugin ---> mpmru against " + ntuser_matchdir + "\n")
		call(vars.riploc + " -r " + ntuser_matchdir + " -p " + "mpmru" + " >> " + self.ntuserpath + "\\mpmru.txt", shell=True)
		print("Running RegRipper plugin ---> mspaper against " + ntuser_matchdir + "\n")
		call(vars.riploc + " -r " + ntuser_matchdir + " -p " + "mspaper" + " >> " + self.ntuserpath + "\\mspaper.txt", shell=True)
		print("Running RegRipper plugin ---> muicache against " + ntuser_matchdir + "\n")
		call(vars.riploc + " -r " + ntuser_matchdir + " -p " + "muicache" + " >> " + self.ntuserpath + "\\muicache.txt", shell=True)
		print("Running RegRipper plugin ---> nero against " + ntuser_matchdir + "\n")
		call(vars.riploc + " -r " + ntuser_matchdir + " -p " + "nero" + " >> " + self.ntuserpath + "\\nero.txt", shell=True)
		print("Running RegRipper plugin ---> netassist against " + ntuser_matchdir + "\n")
		call(vars.riploc + " -r " + ntuser_matchdir + " -p " + "netassist" + " >> " + self.ntuserpath + "\\netassist.txt", shell=True)
		print("Running RegRipper plugin ---> odysseus against " + ntuser_matchdir + "\n")
		call(vars.riploc + " -r " + ntuser_matchdir + " -p " + "odysseus" + " >> " + self.ntuserpath + "\\odysseus.txt", shell=True)
		print("Running RegRipper plugin ---> officedocs against " + ntuser_matchdir + "\n")
		call(vars.riploc + " -r " + ntuser_matchdir + " -p " + "officedocs" + " >> " + self.ntuserpath + "\\officedocs.txt", shell=True)
		print("Running RegRipper plugin ---> oisc against " + ntuser_matchdir + "\n")
		call(vars.riploc + " -r " + ntuser_matchdir + " -p " + "oisc" + " >> " + self.ntuserpath + "\\oisc.txt", shell=True)
		print("Running RegRipper plugin ---> outlook against " + ntuser_matchdir + "\n")
		call(vars.riploc + " -r " + ntuser_matchdir + " -p " + "outlook" + " >> " + self.ntuserpath + "\\outlook.txt", shell=True)
		print("Running RegRipper plugin ---> policies_u against " + ntuser_matchdir + "\n")
		call(vars.riploc + " -r " + ntuser_matchdir + " -p " + "policies_u" + " >> " + self.ntuserpath + "\\policies_u.txt", shell=True)
		print("Running RegRipper plugin ---> printermru against " + ntuser_matchdir + "\n")
		call(vars.riploc + " -r " + ntuser_matchdir + " -p " + "printermru" + " > " + self.ntuserpath + "\\printermru.txt", shell=True)
		print("Running RegRipper plugin ---> printers against " + ntuser_matchdir + "\n")
		call(vars.riploc + " -r " + ntuser_matchdir + " -p " + "printers" + " >> " + self.ntuserpath + "\\printers.txt", shell=True)
		print("Running RegRipper plugin ---> privoxy against " + ntuser_matchdir + "\n")
		call(vars.riploc + " -r " + ntuser_matchdir + " -p " + "privoxy" + " >> " + self.ntuserpath + "\\privoxy.txt", shell=True)
		print("Running RegRipper plugin ---> proxysettings against " + ntuser_matchdir + "\n")
		call(vars.riploc + " -r " + ntuser_matchdir + " -p " + "proxysettings" + " >> " + self.ntuserpath + "\\proxysettings.txt", shell=True)
		print("Running RegRipper plugin ---> publishingwizard against " + ntuser_matchdir + "\n")
		call(vars.riploc + " -r " + ntuser_matchdir + " -p " + "publishingwizard" + " >> " + self.ntuserpath + "\\publishingwizard.txt", shell=True)
		print("Running RegRipper plugin ---> putty against " + ntuser_matchdir + "\n")
		call(vars.riploc + " -r " + ntuser_matchdir + " -p " + "putty" + " >> " + self.ntuserpath + "\\putty.txt", shell=True)
		print("Running RegRipper plugin ---> rdphint against " + ntuser_matchdir + "\n")
		call(vars.riploc + " -r " + ntuser_matchdir + " -p " + "rdphint" + " >> " + self.ntuserpath + "\\rdphint.txt", shell=True)
		print("Running RegRipper plugin ---> realplayer6 against " + ntuser_matchdir + "\n")
		call(vars.riploc + " -r " + ntuser_matchdir + " -p " + "realplayer6" + " >> " + self.ntuserpath + "\\realplayer6.txt", shell=True)
		print("Running RegRipper plugin ---> realvnc against " + ntuser_matchdir + "\n")
		call(vars.riploc + " -r " + ntuser_matchdir + " -p " + "realvnc" + " >> " + self.ntuserpath + "\\realvnc.txt", shell=True)
		print("Running RegRipper plugin ---> recentdocs against " + ntuser_matchdir + "\n")
		call(vars.riploc + " -r " + ntuser_matchdir + " -p " + "recentdocs" + " >> " + self.ntuserpath + "\\recentdocs.txt", shell=True)
		print("Running RegRipper plugin ---> rootkit_revealer against " + ntuser_matchdir + "\n")
		call(vars.riploc + " -r " + ntuser_matchdir + " -p " + "rootkit_revealer" + " >> " + self.ntuserpath + "\\rootkit_revealer.txt", shell=True)
		print("Running RegRipper plugin ---> runmru against " + ntuser_matchdir + "\n")
		call(vars.riploc + " -r " + ntuser_matchdir + " -p " + "runmru" + " >> " + self.ntuserpath + "\\runmru.txt", shell=True)
		print("Running RegRipper plugin ---> sevenzip against " + ntuser_matchdir + "\n")
		call(vars.riploc + " -r " + ntuser_matchdir + " -p " + "sevenzip" + " >> " + self.ntuserpath + "\\sevenzip.txt", shell=True)
		print("Running RegRipper plugin ---> shellfolders against " + ntuser_matchdir + "\n")
		call(vars.riploc + " -r " + ntuser_matchdir + " -p " + "shellfolders" + " >> " + self.ntuserpath + "\\shellfolders.txt", shell=True)
		print("Running RegRipper plugin ---> skype against " + ntuser_matchdir + "\n")
		call(vars.riploc + " -r " + ntuser_matchdir + " -p " + "skype" + " >> " + self.ntuserpath + "\\skype.txt", shell=True)
		print("Running RegRipper plugin ---> snapshot_viewer against " + ntuser_matchdir + "\n")
		call(vars.riploc + " -r " + ntuser_matchdir + " -p " + "snapshot_viewer" + " >> " + self.ntuserpath + "\\snapshot_viewer.txt", shell=True)
		print("Running RegRipper plugin ---> startmenuinternetapps_cu against " + ntuser_matchdir + "\n")
		call(vars.riploc + " -r " + ntuser_matchdir + " -p " + "startmenuinternetapps_cu" + " >> " + self.ntuserpath + "\\startmenuinternetapps_cu.txt", shell=True)
		print("Running RegRipper plugin ---> startpage against " + ntuser_matchdir + "\n")
		call(vars.riploc + " -r " + ntuser_matchdir + " -p " + "startpage" + " >> " + self.ntuserpath + "\\startpage.txt", shell=True)
		print("Running RegRipper plugin ---> streammru against " + ntuser_matchdir + "\n")
		call(vars.riploc + " -r " + ntuser_matchdir + " -p " + "streammru" + " >> " + self.ntuserpath + "\\streammru.txt", shell=True)
		print("Running RegRipper plugin ---> streams against " + ntuser_matchdir + "\n")
		call(vars.riploc + " -r " + ntuser_matchdir + " -p " + "streams" + " >> " + self.ntuserpath + "\\streams.txt", shell=True)
		print("Running RegRipper plugin ---> tsclient against " + ntuser_matchdir + "\n")
		call(vars.riploc + " -r " + ntuser_matchdir + " -p " + "tsclient" + " >> " + self.ntuserpath + "\\tsclient.txt", shell=True)
		print("Running RegRipper plugin ---> typedpaths against " + ntuser_matchdir + "\n")
		call(vars.riploc + " -r " + ntuser_matchdir + " -p " + "typedpaths" + " >> " + self.ntuserpath + "\\typedpaths.txt", shell=True)
		print("Running RegRipper plugin ---> typedurls against " + ntuser_matchdir + "\n")
		call(vars.riploc + " -r " + ntuser_matchdir + " -p " + "typedurls" + " >> " + self.ntuserpath + "\\typedurls.txt", shell=True)
		print("Running RegRipper plugin ---> unreadmail against " + ntuser_matchdir + "\n")
		call(vars.riploc + " -r " + ntuser_matchdir + " -p " + "unreadmail" + " >> " + self.ntuserpath + "\\unreadmail.txt", shell=True)
		print("Running RegRipper plugin ---> user_run against " + ntuser_matchdir + "\n")
		call(vars.riploc + " -r " + ntuser_matchdir + " -p " + "user_run" + " >> " + self.ntuserpath + "\\user_run.txt", shell=True)
		print("Running RegRipper plugin ---> userassist against " + ntuser_matchdir + "\n")
		call(vars.riploc + " -r " + ntuser_matchdir + " -p " + "userassist" + " >> " + self.ntuserpath + "\\userassist.txt", shell=True)
		print("Running RegRipper plugin ---> userassist2 against " + ntuser_matchdir + "\n")
		call(vars.riploc + " -r " + ntuser_matchdir + " -p " + "userassist2" + " >> " + self.ntuserpath + "\\userassist2.txt", shell=True)
		print("Running RegRipper plugin ---> userlocsvc against " + ntuser_matchdir + "\n")
		call(vars.riploc + " -r " + ntuser_matchdir + " -p " + "userlocsvc" + " >> " + self.ntuserpath + "\\userlocsvc.txt", shell=True)
		print("Running RegRipper plugin ---> vista_bitbucket against " + ntuser_matchdir + "\n")
		call(vars.riploc + " -r " + ntuser_matchdir + " -p " + "vista_bitbucket" + " >> " + self.ntuserpath + "\\vista_bitbucket.txt", shell=True)
		print("Running RegRipper plugin ---> vista_comdlg32 against " + ntuser_matchdir + "\n")
		call(vars.riploc + " -r " + ntuser_matchdir + " -p " + "vista_comdlg32" + " >> " + self.ntuserpath + "\\vista_comdlg32.txt", shell=True)
		print("Running RegRipper plugin ---> vmplayer against " + ntuser_matchdir + "\n")
		call(vars.riploc + " -r " + ntuser_matchdir + " -p " + "vmplayer" + " >> " + self.ntuserpath + "\\vmplayer.txt", shell=True)
		print("Running RegRipper plugin ---> vmware_vsphere_client against " + ntuser_matchdir + "\n")
		call(vars.riploc + " -r " + ntuser_matchdir + " -p " + "vmware_vsphere_client" + " >> " + self.ntuserpath + "\\vmware_vsphere_client.txt", shell=True)
		print("Running RegRipper plugin ---> vnchooksapplicationprefs against " + ntuser_matchdir + "\n")
		call(vars.riploc + " -r " + ntuser_matchdir + " -p " + "vnchooksapplicationprefs" + " >> " + self.ntuserpath + "\\vnchooksapplicationprefs.txt", shell=True)
		print("Running RegRipper plugin ---> vncviewer against " + ntuser_matchdir + "\n")
		call(vars.riploc + " -r " + ntuser_matchdir + " -p " + "vncviewer" + " >> " + self.ntuserpath + "\\vncviewer.txt", shell=True)
		print("Running RegRipper plugin ---> wallpaper against " + ntuser_matchdir + "\n")
		call(vars.riploc + " -r " + ntuser_matchdir + " -p " + "wallpaper" + " >> " + self.ntuserpath + "\\wallpaper.txt", shell=True)
		print("Running RegRipper plugin ---> warcraft3 against " + ntuser_matchdir + "\n")
		call(vars.riploc + " -r " + ntuser_matchdir + " -p " + "warcraft3" + " >> " + self.ntuserpath + "\\warcraft3.txt", shell=True)
		print("Running RegRipper plugin ---> win7_ua against " + ntuser_matchdir + "\n")
		call(vars.riploc + " -r " + ntuser_matchdir + " -p " + "win7_ua" + " >> " + self.ntuserpath + "\\win7_ua.txt", shell=True)
		print("Running RegRipper plugin ---> winlogon_u against " + ntuser_matchdir + "\n")
		call(vars.riploc + " -r " + ntuser_matchdir + " -p " + "winlogon_u" + " >> " + self.ntuserpath + "\\winlogon_u.txt", shell=True)
		print("Running RegRipper plugin ---> winrar against " + ntuser_matchdir + "\n")
		call(vars.riploc + " -r " + ntuser_matchdir + " -p " + "winrar" + " >> " + self.ntuserpath + "\\winrar.txt", shell=True)
		print("Running RegRipper plugin ---> winvnc against " + ntuser_matchdir + "\n")
		call(vars.riploc + " -r " + ntuser_matchdir + " -p " + "winvnc" + " >> " + self.ntuserpath + "\\winvnc.txt", shell=True)
		print("Running RegRipper plugin ---> winzip against " + ntuser_matchdir + "\n")
		call(vars.riploc + " -r " + ntuser_matchdir + " -p " + "winzip" + " >> " + self.ntuserpath + "\\winzip.txt", shell=True)
		print("Running RegRipper plugin ---> wordwheelquery against " + ntuser_matchdir + "\n")
		call(vars.riploc + " -r " + ntuser_matchdir + " -p " + "wordwheelquery" + " >> " + self.ntuserpath + "\\wordwheelquery.txt", shell=True)
		print("Running RegRipper plugin ---> yahoo_cu against " + ntuser_matchdir + "\n")
		call(vars.riploc + " -r " + ntuser_matchdir + " -p " + "yahoo_cu" + " >> " + self.ntuserpath + "\\yahoo_cu.txt", shell=True)

	def rip_sam(self,sam_matchdir):
		"""SAM Ripping"""
		sam_matchdir = sam_matchdir
		#temp_sam_dir = temp_sam_dir
		print("Running RegRipper plugin ---> samparse against " + sam_matchdir + "\n")
		call(vars.riploc + " -r " + sam_matchdir + " -p " + "samparse" + " >> " + self.sampath + "\\samparse.txt", shell=True)
		print("Running RegRipper plugin ---> samparse2 against " + sam_matchdir + "\n")
		call(vars.riploc + " -r " + sam_matchdir + " -p " + "samparse2" + " >> " + self.sampath + "\\samparse2.txt", shell=True)
		
	def rip_security(self,security_matchdir):
		"""Security Ripping"""
		security_matchdir = security_matchdir
		#temp_security_dir = temp_security_dir
		print("Running RegRipper plugin ---> auditpol against " + security_matchdir + "\n")
		call(vars.riploc + " -r " + security_matchdir + " -p " + "auditpol" + " >> " + self.secpath + "\\auditpol.txt", shell=True)
		print("Running RegRipper plugin ---> lsasecrets against " + security_matchdir + "\n")
		call(vars.riploc + " -r " + security_matchdir + " -p " + "lsasecrets" + " >> " + self.secpath + "\\lsasecrets.txt", shell=True)
		print("Running RegRipper plugin ---> polacdms against " + security_matchdir + "\n")
		call(vars.riploc + " -r " + security_matchdir + " -p " + "polacdms" + " >> " + self.secpath + "\\polacdms.txt", shell=True)
		
	def rip_software(self,software_matchdir):
		"""Software Ripping"""
		software_matchdir = software_matchdir
		#temp_software_dir = temp_software_dir
		print("Running RegRipper plugin ---> appinitdlls against " + software_matchdir + "\n")
		call(vars.riploc + " -r " + software_matchdir + " -p " + "appinitdlls" + " >> " + self.softpath + "\\appinitdlls.txt", shell=True)
		print("Running RegRipper plugin ---> apppaths against " + software_matchdir + "\n")
		call(vars.riploc + " -r " + software_matchdir + " -p " + "apppaths" + " >> " + self.softpath + "\\apppaths.txt", shell=True)
		print("Running RegRipper plugin ---> assoc against " + software_matchdir + "\n")
		call(vars.riploc + " -r " + software_matchdir + " -p " + "assoc" + " >> " + self.softpath + "\\assoc.txt", shell=True)
		print("Running RegRipper plugin ---> banner against " + software_matchdir + "\n")
		call(vars.riploc + " -r " + software_matchdir + " -p " + "banner" + " >> " + self.softpath + "\\banner.txt", shell=True)
		print("Running RegRipper plugin ---> bho against " + software_matchdir + "\n")
		call(vars.riploc + " -r " + software_matchdir + " -p " + "bho" + " >> " + self.softpath + "\\bho.txt", shell=True)
		print("Running RegRipper plugin ---> bitbucket against " + software_matchdir + "\n")
		call(vars.riploc + " -r " + software_matchdir + " -p " + "bitbucket" + " >> " + self.softpath + "\\bitbucket.txt", shell=True)
		print("Running RegRipper plugin ---> clsid against " + software_matchdir + "\n")
		call(vars.riploc + " -r " + software_matchdir + " -p " + "clsid" + " >> " + self.softpath + "\\clsid.txt", shell=True)
		print("Running RegRipper plugin ---> cmd_shell against " + software_matchdir + "\n")
		call(vars.riploc + " -r " + software_matchdir + " -p " + "cmd_shell" + " >> " + self.softpath + "\\cmd_shell.txt", shell=True)
		print("Running RegRipper plugin ---> codeid against " + software_matchdir + "\n")
		call(vars.riploc + " -r " + software_matchdir + " -p " + "codeid" + " >> " + self.softpath + "\\codeid.txt", shell=True)
		print("Running RegRipper plugin ---> ctrlpnl against " + software_matchdir + "\n")
		call(vars.riploc + " -r " + software_matchdir + " -p " + "ctrlpnl" + " >> " + self.softpath + "\\ctrlpnl.txt", shell=True)
		print("Running RegRipper plugin ---> defbrowser against " + software_matchdir + "\n")
		call(vars.riploc + " -r " + software_matchdir + " -p " + "defbrowser" + " >> " + self.softpath + "\\defbrowser.txt", shell=True)
		print("Running RegRipper plugin ---> drwatson against " + software_matchdir + "\n")
		call(vars.riploc + " -r " + software_matchdir + " -p " + "drwatson" + " >> " + self.softpath + "\\drwatson.txt", shell=True)
		print("Running RegRipper plugin ---> ie_version against " + software_matchdir + "\n")
		call(vars.riploc + " -r " + software_matchdir + " -p " + "ie_version" + " >> " + self.softpath + "\\ie_version.txt", shell=True)
		print("Running RegRipper plugin ---> polacdms against " + software_matchdir + "\n")
		call(vars.riploc + " -r " + software_matchdir + " -p " + "polacdms" + " >> " + self.softpath + "\\imagefile.txt", shell=True)
		print("Running RegRipper plugin ---> imagefile against " + software_matchdir + "\n")
		call(vars.riploc + " -r " + software_matchdir + " -p " + "imagefile" + " >> " + self.softpath + "\\init_dlls.txt", shell=True)
		print("Running RegRipper plugin ---> installedcomp against " + software_matchdir + "\n")
		call(vars.riploc + " -r " + software_matchdir + " -p " + "installedcomp" + " >> " + self.softpath + "\\installedcomp.txt", shell=True)
		print("Running RegRipper plugin ---> javafx against " + software_matchdir + "\n")
		call(vars.riploc + " -r " + software_matchdir + " -p " + "javafx" + " >> " + self.softpath + "\\javafx.txt", shell=True)
		print("Running RegRipper plugin ---> kb950582 against " + software_matchdir + "\n")
		call(vars.riploc + " -r " + software_matchdir + " -p " + "kb950582" + " >> " + self.softpath + "\\kb950582.txt", shell=True)
		print("Running RegRipper plugin ---> landesk against " + software_matchdir + "\n")
		call(vars.riploc + " -r " + software_matchdir + " -p " + "landesk" + " >> " + self.softpath + "\\landesk.txt", shell=True)
		print("Running RegRipper plugin ---> macaddr against " + software_matchdir + "\n")
		call(vars.riploc + " -r " + software_matchdir + " -p " + "macaddr" + " >> " + self.softpath + "\\macaddr.txt", shell=True)
		print("Running RegRipper plugin ---> mrt against " + software_matchdir + "\n")
		call(vars.riploc + " -r " + software_matchdir + " -p " + "mrt" + " >> " + self.softpath + "\\mrt.txt", shell=True)
		print("Running RegRipper plugin ---> msis against " + software_matchdir + "\n")
		call(vars.riploc + " -r " + software_matchdir + " -p " + "msis" + " >> " + self.softpath + "\\msis.txt", shell=True)
		print("Running RegRipper plugin ---> networkcards against " + software_matchdir + "\n")
		call(vars.riploc + " -r " + software_matchdir + " -p " + "networkcards" + " >> " + self.softpath + "\\networkcards.txt", shell=True)
		print("Running RegRipper plugin ---> networklist against " + software_matchdir + "\n")
		call(vars.riploc + " -r " + software_matchdir + " -p " + "networklist" + " >> " + self.softpath + "\\networklist.txt", shell=True)
		print("Running RegRipper plugin ---> networkuid against " + software_matchdir + "\n")
		call(vars.riploc + " -r " + software_matchdir + " -p " + "networkuid" + " >> " + self.softpath + "\\networkuid.txt", shell=True)
		print("Running RegRipper plugin ---> notify against " + software_matchdir + "\n")
		call(vars.riploc + " -r " + software_matchdir + " -p " + "notify" + " >> " + self.softpath + "\\notify.txt", shell=True)
		print("Running RegRipper plugin ---> port_dev against " + software_matchdir + "\n")
		call(vars.riploc + " -r " + software_matchdir + " -p " + "port_dev" + " >> " + self.softpath + "\\port_dev.txt", shell=True)
		print("Running RegRipper plugin ---> product against " + software_matchdir + "\n")
		call(vars.riploc + " -r " + software_matchdir + " -p " + "product" + " >> " + self.softpath + "\\product.txt", shell=True)
		print("Running RegRipper plugin ---> profilelist against " + software_matchdir + "\n")
		call(vars.riploc + " -r " + software_matchdir + " -p " + "profilelist" + " >> " + self.softpath + "\\profilelist.txt", shell=True)
		print("Running RegRipper plugin ---> regback against " + software_matchdir + "\n")
		call(vars.riploc + " -r " + software_matchdir + " -p " + "regback" + " >> " + self.softpath + "\\regback.txt", shell=True)
		print("Running RegRipper plugin ---> removdev against " + software_matchdir + "\n")
		call(vars.riploc + " -r " + software_matchdir + " -p " + "removdev" + " >> " + self.softpath + "\\removdev.txt", shell=True)
		print("Running RegRipper plugin ---> renocide against " + software_matchdir + "\n")
		call(vars.riploc + " -r " + software_matchdir + " -p " + "renocide" + " >> " + self.softpath + "\\renocide.txt", shell=True)
		print("Running RegRipper plugin ---> schedagent against " + software_matchdir + "\n")
		call(vars.riploc + " -r " + software_matchdir + " -p " + "schedagent" + " >> " + self.softpath + "\\schedagent.txt", shell=True)
		print("Running RegRipper plugin ---> secctr against " + software_matchdir + "\n")
		call(vars.riploc + " -r " + software_matchdir + " -p " + "secctr" + " >> " + self.softpath + "\\secctr.txt", shell=True)
		print("Running RegRipper plugin ---> sfc against " + software_matchdir + "\n")
		call(vars.riploc + " -r " + software_matchdir + " -p " + "sfc" + " >> " + self.softpath + "\\sfc.txt", shell=True)
		print("Running RegRipper plugin ---> shellexec against " + software_matchdir + "\n")
		call(vars.riploc + " -r " + software_matchdir + " -p " + "shellexec" + " >> " + self.softpath + "\\shellexec.txt", shell=True)
		print("Running RegRipper plugin ---> shellext against " + software_matchdir + "\n")
		call(vars.riploc + " -r " + software_matchdir + " -p " + "shellext" + " >> " + self.softpath + "\\shellext.txt", shell=True)
		print("Running RegRipper plugin ---> shelloverlay against " + software_matchdir + "\n")
		call(vars.riploc + " -r " + software_matchdir + " -p " + "shelloverlay" + " >> " + self.softpath + "\\shelloverlay.txt", shell=True)
		print("Running RegRipper plugin ---> snapshot against " + software_matchdir + "\n")
		call(vars.riploc + " -r " + software_matchdir + " -p " + "snapshot" + " >> " + self.softpath + "\\snapshot.txt", shell=True)
		print("Running RegRipper plugin ---> soft_run against " + software_matchdir + "\n")
		call(vars.riploc + " -r " + software_matchdir + " -p " + "soft_run" + " >> " + self.softpath + "\\soft_run.txt", shell=True)
		print("Running RegRipper plugin ---> specaccts against " + software_matchdir + "\n")
		call(vars.riploc + " -r " + software_matchdir + " -p " + "specaccts" + " >> " + self.softpath + "\\specaccts.txt", shell=True)
		print("Running RegRipper plugin ---> sql_lastconnect against " + software_matchdir + "\n")
		call(vars.riploc + " -r " + software_matchdir + " -p " + "sql_lastconnect" + " >> " + self.softpath + "\\sql_lastconnect.txt", shell=True)
		print("Running RegRipper plugin ---> ssid against " + software_matchdir + "\n")
		call(vars.riploc + " -r " + software_matchdir + " -p " + "ssid" + " >> " + self.softpath + "\\ssid.txt", shell=True)
		print("Running RegRipper plugin ---> startmenuinternetapps_lm against " + software_matchdir + "\n")
		call(vars.riploc + " -r " + software_matchdir + " -p " + "startmenuinternetapps_lm" + " >> " + self.softpath + "\\startmenuinternetapps_lm.txt", shell=True)
		print("Running RegRipper plugin ---> svchost against " + software_matchdir + "\n")
		call(vars.riploc + " -r " + software_matchdir + " -p " + "svchost" + " >> " + self.softpath + "\\svchost.txt", shell=True)
		print("Running RegRipper plugin ---> taskman against " + software_matchdir + "\n")
		call(vars.riploc + " -r " + software_matchdir + " -p " + "taskman" + " >> " + self.softpath + "\\taskman.txt", shell=True)
		print("Running RegRipper plugin ---> uninstall against " + software_matchdir + "\n")
		call(vars.riploc + " -r " + software_matchdir + " -p " + "uninstall" + " >> " + self.softpath + "\\uninstall.txt", shell=True)
		print("Running RegRipper plugin ---> urlzone against " + software_matchdir + "\n")
		call(vars.riploc + " -r " + software_matchdir + " -p " + "urlzone" + " >> " + self.softpath + "\\urlzone.txt", shell=True)
		print("Running RegRipper plugin ---> userinit against " + software_matchdir + "\n")
		call(vars.riploc + " -r " + software_matchdir + " -p " + "userinit" + " >> " + self.softpath + "\\userinit.txt", shell=True)
		print("Running RegRipper plugin ---> virut against " + software_matchdir + "\n")
		call(vars.riploc + " -r " + software_matchdir + " -p " + "virut" + " >> " + self.softpath + "\\virut.txt", shell=True)
		print("Running RegRipper plugin ---> vista_wireless against " + software_matchdir + "\n")
		call(vars.riploc + " -r " + software_matchdir + " -p " + "vista_wireless" + " >> " + self.softpath + "\\vista_wireless.txt", shell=True)
		print("Running RegRipper plugin ---> win_cv against " + software_matchdir + "\n")
		call(vars.riploc + " -r " + software_matchdir + " -p " + "win_cv" + " >> " + self.softpath + "\\win_cv.txt", shell=True)
		print("Running RegRipper plugin ---> win_ua against " + software_matchdir + "\n")
		call(vars.riploc + " -r " + software_matchdir + " -p " + "win_ua" + " >> " + self.softpath + "\\win_ua.txt", shell=True)
		print("Running RegRipper plugin ---> winlogon against " + software_matchdir + "\n")
		call(vars.riploc + " -r " + software_matchdir + " -p " + "winlogon" + " >> " + self.softpath + "\\winlogon.txt", shell=True)
		print("Running RegRipper plugin ---> winnt_cv against " + software_matchdir + "\n")
		call(vars.riploc + " -r " + software_matchdir + " -p " + "winnt_cv" + " >> " + self.softpath + "\\winnt_cv.txt", shell=True)
		print("Running RegRipper plugin ---> winver against " + software_matchdir + "\n")
		call(vars.riploc + " -r " + software_matchdir + " -p " + "winver" + " >> " + self.softpath + "\\winver.txt", shell=True)
		print("Running RegRipper plugin ---> yahoo_lm against " + software_matchdir + "\n")
		call(vars.riploc + " -r " + software_matchdir + " -p " + "yahoo_lm" + " >> " + self.softpath + "\\yahoo_lm.txt", shell=True)
		
	def rip_system(self,system_matchdir):
		"""System Ripping"""
		system_matchdir = system_matchdir
		#temp_system_dir = temp_system_dir
		print("Running RegRipper plugin ---> auditfail against " + system_matchdir + "\n")
		call(vars.riploc + " -r " + system_matchdir + " -p " + "auditfail" + " >> " + self.syspath + "\\auditfail.txt", shell=True)
		print("Running RegRipper plugin ---> compname against " + system_matchdir + "\n")
		call(vars.riploc + " -r " + system_matchdir + " -p " + "compname" + " >> " + self.syspath + "\\compname.txt", shell=True)
		print("Running RegRipper plugin ---> crashcontrol against " + system_matchdir + "\n")
		call(vars.riploc + " -r " + system_matchdir + " -p " + "crashcontrol" + " >> " + self.syspath + "\\crashcontrol.txt", shell=True)
		print("Running RegRipper plugin ---> crashdump against " + system_matchdir + "\n")
		call(vars.riploc + " -r " + system_matchdir + " -p " + "crashdump" + " >> " + self.syspath + "\\crashdump.txt", shell=True)
		print("Running RegRipper plugin ---> ddm against " + system_matchdir + "\n")
		call(vars.riploc + " -r " + system_matchdir + " -p " + "ddm" + " >> " + self.syspath + "\\ddm.txt", shell=True)
		print("Running RegRipper plugin ---> devclass against " + system_matchdir + "\n")
		call(vars.riploc + " -r " + system_matchdir + " -p " + "devclass" + " >> " + self.syspath + "\\devclass.txt", shell=True)
		print("Running RegRipper plugin ---> disablelastaccess against " + system_matchdir + "\n")
		call(vars.riploc + " -r " + system_matchdir + " -p " + "disablelastaccess" + " >> " + self.syspath + "\\disablelastaccess.txt", shell=True)
		print("Running RegRipper plugin ---> dllsearch against " + system_matchdir + "\n")
		call(vars.riploc + " -r " + system_matchdir + " -p " + "dllsearch" + " >> " + self.syspath + "\\dllsearch.txt", shell=True)
		print("Running RegRipper plugin ---> eventlog against " + system_matchdir + "\n")
		call(vars.riploc + " -r " + system_matchdir + " -p " + "eventlog" + " >> " + self.syspath + "\\eventlog.txt", shell=True)
		print("Running RegRipper plugin ---> fw_config against " + system_matchdir + "\n")
		call(vars.riploc + " -r " + system_matchdir + " -p " + "fw_config" + " >> " + self.syspath + "\\fw_config.txt", shell=True)
		print("Running RegRipper plugin ---> hibernate against " + system_matchdir + "\n")
		call(vars.riploc + " -r " + system_matchdir + " -p " + "hibernate" + " >> " + self.syspath + "\\hibernate.txt", shell=True)
		print("Running RegRipper plugin ---> ide against " + system_matchdir + "\n")
		call(vars.riploc + " -r " + system_matchdir + " -p " + "ide" + " >> " + self.syspath + "\\ide.txt", shell=True)
		print("Running RegRipper plugin ---> imagedev against " + system_matchdir + "\n")
		call(vars.riploc + " -r " + system_matchdir + " -p " + "imagedev" + " >> " + self.syspath + "\\imagedev.txt", shell=True)
		print("Running RegRipper plugin ---> kbdcrash against " + system_matchdir + "\n")
		call(vars.riploc + " -r " + system_matchdir + " -p " + "kbdcrash" + " >> " + self.syspath + "\\kbdcrash.txt", shell=True)
		print("Running RegRipper plugin ---> legacy against " + system_matchdir + "\n")
		call(vars.riploc + " -r " + system_matchdir + " -p " + "legacy" + " >> " + self.syspath + "\\legacy.txt", shell=True)
		print("Running RegRipper plugin ---> mountdev against " + system_matchdir + "\n")
		call(vars.riploc + " -r " + system_matchdir + " -p " + "mountdev" + " >> " + self.syspath + "\\mountdev.txt", shell=True)
		print("Running RegRipper plugin ---> mountdev2 against " + system_matchdir + "\n")
		call(vars.riploc + " -r " + system_matchdir + " -p " + "mountdev2" + " >> " + self.syspath + "\\mountdev2.txt", shell=True)
		print("Running RegRipper plugin ---> mountdev3 against " + system_matchdir + "\n")
		call(vars.riploc + " -r " + system_matchdir + " -p " + "mountdev3" + " >> " + self.syspath + "\\mountdev3.txt", shell=True)
		print("Running RegRipper plugin ---> network against " + system_matchdir + "\n")
		call(vars.riploc + " -r " + system_matchdir + " -p " + "network" + " >> " + self.syspath + "\\network.txt", shell=True)
		print("Running RegRipper plugin ---> nic against " + system_matchdir + "\n")
		call(vars.riploc + " -r " + system_matchdir + " -p " + "nic" + " >> " + self.syspath + "\\nic.txt", shell=True)
		print("Running RegRipper plugin ---> nic2 against " + system_matchdir + "\n")
		call(vars.riploc + " -r " + system_matchdir + " -p " + "nic2" + " >> " + self.syspath + "\\nic2.txt", shell=True)
		print("Running RegRipper plugin ---> nic_mst2 against " + system_matchdir + "\n")
		call(vars.riploc + " -r " + system_matchdir + " -p " + "nic_mst2" + " >> " + self.syspath + "\\nic_mst2.txt", shell=True)
		print("Running RegRipper plugin ---> nolmhash against " + system_matchdir + "\n")
		call(vars.riploc + " -r " + system_matchdir + " -p " + "nolmhash" + " >> " + self.syspath + "\\nolmhash.txt", shell=True)
		print("Running RegRipper plugin ---> pagefile against " + system_matchdir + "\n")
		call(vars.riploc + " -r " + system_matchdir + " -p " + "pagefile" + " >> " + self.syspath + "\\pagefile.txt", shell=True)
		# print("Running RegRipper plugin ---> productpolicy against " + system_matchdir + "\n")
		# call(vars.riploc + " -r " + system_matchdir + " -p " + "productpolicy" + " >> " + self.syspath + "\\productpolicy.txt", shell=True)
		print("Running RegRipper plugin ---> producttype against " + system_matchdir + "\n")
		call(vars.riploc + " -r " + system_matchdir + " -p " + "producttype" + " >> " + self.syspath + "\\producttype.txt", shell=True)
		print("Running RegRipper plugin ---> rdpport against " + system_matchdir + "\n")
		call(vars.riploc + " -r " + system_matchdir + " -p " + "rdpport" + " >> " + self.syspath + "\\rdpport.txt", shell=True)
		print("Running RegRipper plugin ---> routes against " + system_matchdir + "\n")
		call(vars.riploc + " -r " + system_matchdir + " -p " + "routes" + " >> " + self.syspath + "\\routes.txt", shell=True)
		print("Running RegRipper plugin ---> safeboot against " + system_matchdir + "\n")
		call(vars.riploc + " -r " + system_matchdir + " -p " + "safeboot" + " >> " + self.syspath + "\\safeboot.txt", shell=True)
		print("Running RegRipper plugin ---> services against " + system_matchdir + "\n")
		call(vars.riploc + " -r " + system_matchdir + " -p " + "services" + " >> " + self.syspath + "\\services.txt", shell=True)
		print("Running RegRipper plugin ---> shares against " + system_matchdir + "\n")
		call(vars.riploc + " -r " + system_matchdir + " -p " + "shares" + " >> " + self.syspath + "\\shares.txt", shell=True)
		print("Running RegRipper plugin ---> shutdown against " + system_matchdir + "\n")
		call(vars.riploc + " -r " + system_matchdir + " -p " + "shutdown" + " >> " + self.syspath + "\\shutdown.txt", shell=True)
		print("Running RegRipper plugin ---> shutdowncount against " + system_matchdir + "\n")
		call(vars.riploc + " -r " + system_matchdir + " -p " + "shutdowncount" + " >> " + self.syspath + "\\shutdowncount.txt", shell=True)
		print("Running RegRipper plugin ---> stillimage against " + system_matchdir + "\n")
		call(vars.riploc + " -r " + system_matchdir + " -p " + "stillimage" + " >> " + self.syspath + "\\stillimage.txt", shell=True)
		print("Running RegRipper plugin ---> svc against " + system_matchdir + "\n")
		call(vars.riploc + " -r " + system_matchdir + " -p " + "svc" + " >> " + self.syspath + "\\svc.txt", shell=True)
		print("Running RegRipper plugin ---> svc2 against " + system_matchdir + "\n")
		call(vars.riploc + " -r " + system_matchdir + " -p " + "svc2" + " >> " + self.syspath + "\\svc2.txt", shell=True)
		print("Running RegRipper plugin ---> svcdll against " + system_matchdir + "\n")
		call(vars.riploc + " -r " + system_matchdir + " -p " + "svcdll" + " >> " + self.syspath + "\\svcdll.txt", shell=True)
		print("Running RegRipper plugin ---> termserv against " + system_matchdir + "\n")
		call(vars.riploc + " -r " + system_matchdir + " -p " + "termserv" + " >> " + self.syspath + "\\termserv.txt", shell=True)
		print("Running RegRipper plugin ---> timezone against " + system_matchdir + "\n")
		call(vars.riploc + " -r " + system_matchdir + " -p " + "timezone" + " >> " + self.syspath + "\\timezone.txt", shell=True)
		print("Running RegRipper plugin ---> timezone2 against " + system_matchdir + "\n")
		call(vars.riploc + " -r " + system_matchdir + " -p " + "timezone2" + " >> " + self.syspath + "\\timezone2.txt", shell=True)
		print("Running RegRipper plugin ---> usbdevices against " + system_matchdir + "\n")
		call(vars.riploc + " -r " + system_matchdir + " -p " + "usbdevices" + " >> " + self.syspath + "\\usbdevices.txt", shell=True)
		print("Running RegRipper plugin ---> usbstor against " + system_matchdir + "\n")
		call(vars.riploc + " -r " + system_matchdir + " -p " + "usbstor" + " >> " + self.syspath + "\\usbstor.txt", shell=True)
		print("Running RegRipper plugin ---> usbstor3 against " + system_matchdir + "\n")
		call(vars.riploc + " -r " + system_matchdir + " -p " + "usbstor3" + " >> " + self.syspath + "\\usbstor3.txt", shell=True)
		print("Running RegRipper plugin ---> xpedition against " + system_matchdir + "\n")
		call(vars.riploc + " -r " + system_matchdir + " -p " + "xpedition" + " >> " + self.syspath + "\\xpedition.txt", shell=True)
	
	
	
	def mem_analyze(self):
		""" Volatility instructions"""
		self.pidNumbers = glob.glob(vars.tmp_trgt_dir + "\\MemInfo\\*.dmp")
		path = vars.outputdir + "\\MemInfo\\"
		for root, dir, files in os.walk(path):
			for file in files:
				if "physmem" in file:
					self.memfile = root + "\\" + file
					print("Processing " + self.memfile)
					# raw_input("Press Enter to continue...")
		#self.pidNumbers
		try:
			print("python " + vars.vol_dir + "\\vol.py imageinfo --output=text --output-file=" + vars.outputdir + "\\MemInfo\\imageinfo.txt -f " + self.memfile)
			call("python " + vars.vol_dir + "\\vol.py imageinfo --output=text --output-file=" + vars.outputdir + "\\MemInfo\\imageinfo.txt -f " + self.memfile, shell=True)
			call("files\\src\\grep.exe -i suggested " + vars.outputdir + "\\MemInfo\\imageinfo.txt|files\\src\\tln\\cut.exe -f 2 -d \":\"|files\\src\\tln\\cut.exe -f 1 -d \",\" > " + vars.outputdir + "\\" + "profile.txt", shell=True)
			profile=open(vars.outputdir + "\\profile.txt", 'r')
		except:
			# log.logger.debug
			# If profile fails to be determine because of my bad logic just set it to one
			profile="Win7SP1x86"
			pass
		
		for wintype in profile:
			self.image_profile = wintype.replace(" ","").replace("\n","")
		print(self.image_profile)
		if "WinXP" in self.image_profile:
			print("Outputting Connections")
			call("python " + vars.vol_dir + "\\vol.py --profile=" + self.image_profile + " connections --output=text --output-file=" + vars.outputdir + "\\MemInfo\\connections.txt -f " + self.memfile, shell=True)
			print("Outputting ConnScan")
			call("python " + vars.vol_dir + "\\vol.py --profile=" + self.image_profile + " connscan --output=text --output-file=" + vars.outputdir + "\\MemInfo\\connscan.txt -f " + self.memfile, shell=True)
			print("Outputting Sockets")
			call("python " + vars.vol_dir + "\\vol.py --profile=" + self.image_profile + " sockets --output=text --output-file=" + vars.outputdir + "\\MemInfo\\sockets.txt -f " + self.memfile, shell=True)
			print("Outputting SockScan")
			call("python " + vars.vol_dir + "\\vol.py --profile=" + self.image_profile + " sockscan --output=text --output-file=" + vars.outputdir + "\\MemInfo\\sockscan.txt -f " + self.memfile, shell=True)
		elif "Win7" in self.image_profile:
			print("Outputting Netscan")
			call("python " + vars.vol_dir + "\\vol.py --profile=" + self.image_profile + " netscan --output=text --output-file=" + vars.outputdir + "\\MemInfo\\netscan.txt -f " + self.memfile, shell=True)
			# print("python " + vars.vol_dir + "\\vol.py --profile=" + self.image_profile + " netscan --output=text --output-file=" + vars.outputdir + "\\MemInfo\\netscan.txt -f " + self.memfile)
		print("Outputting PS List")
		call("python " + vars.vol_dir + "\\vol.py --profile=" + self.image_profile + " pslist --output=text --output-file=" + vars.outputdir + "\\MemInfo\\pslist.txt -f " + self.memfile, shell=True)
		# print("Outputting KDBG Scan")
		# call("python " + vars.vol_dir + "\\vol.py --profile=" + self.image_profile + " kdbgscan --output=text --output-file=" + vars.outputdir + "\\MemInfo\\kdbgscan.txt -f " + self.memfile, shell=True)
		# print("Outputting KPCR Scan")
		# call("python " + vars.vol_dir + "\\vol.py --profile=" + self.image_profile + " kpcrscan --output=text --output-file=" + vars.outputdir + "\\MemInfo\\kpcrscan.txt -f " + self.memfile, shell=True)
		print("Outputting PS Tree")
		call("python " + vars.vol_dir + "\\vol.py --profile=" + self.image_profile + " pstree --output=text --output-file=" + vars.outputdir + "\\MemInfo\\pstree.txt -f " + self.memfile, shell=True)
		print("Outputting PS Scan")
		call("python " + vars.vol_dir + "\\vol.py --profile=" + self.image_profile + " psscan --output=text --output-file=" + vars.outputdir + "\\MemInfo\\psscan.txt -f " + self.memfile, shell=True)
		print("Outputting DLL List")
		call("python " + vars.vol_dir + "\\vol.py --profile=" + self.image_profile + " dlllist --output=text --output-file=" + vars.outputdir + "\\MemInfo\\dlllist.txt -f " + self.memfile, shell=True)
		# print("Outputting DLL Dump")
		# call("python " + vars.vol_dir + "\\vol.py --profile=" + self.image_profile + " dlldump --output=text --output-file=" + vars.outputdir + "\\MemInfo\\dlldump.txt -f " + self.memfile, shell=True)
		print("Outputting Handles")
		call("python " + vars.vol_dir + "\\vol.py --profile=" + self.image_profile + " handles --output=text --output-file=" + vars.outputdir + "\\MemInfo\\handles.txt -f " + self.memfile, shell=True)
		print("Outputting SIDS")
		call("python " + vars.vol_dir + "\\vol.py --profile=" + self.image_profile + " getsids --output=text --output-file=" + vars.outputdir + "\\MemInfo\\getsids.txt -f " + self.memfile, shell=True)
		print("Outputting VerInfo")
		call("python " + vars.vol_dir + "\\vol.py --profile=" + self.image_profile + " verinfo --output=text --output-file=" + vars.outputdir + "\\MemInfo\\verinfo.txt -f " + self.memfile, shell=True)
		# print("Outputting MemMap")
		# call("python " + vars.vol_dir + "\\vol.py --profile=" + self.image_profile + " memmap --output=text --output-file=" + vars.outputdir + "\\MemInfo\\memmap.txt -f " + self.memfile, shell=True)
		print("Outputting Vad Walk")
		call("python " + vars.vol_dir + "\\vol.py --profile=" + self.image_profile + " vadwalk --output=text --output-file=" + vars.outputdir + "\\MemInfo\\vadwalk.txt -f " + self.memfile, shell=True)
		print("Outputting Vad Tree")
		call("python " + vars.vol_dir + "\\vol.py --profile=" + self.image_profile + " vadtree --output=text --output-file=" + vars.outputdir + "\\MemInfo\\vadtree.txt -f " + self.memfile, shell=True)
		print("Outputting Vad Info")
		call("python " + vars.vol_dir + "\\vol.py --profile=" + self.image_profile + " vadinfo --output=text --output-file=" + vars.outputdir + "\\MemInfo\\vadinfo.txt -f " + self.memfile, shell=True)
		print("Outputting Modules")
		call("python " + vars.vol_dir + "\\vol.py --profile=" + self.image_profile + " modules --output=text --output-file=" + vars.outputdir + "\\MemInfo\\modules.txt -f " + self.memfile, shell=True)
		print("Outputting Mod Scan")
		call("python " + vars.vol_dir + "\\vol.py --profile=" + self.image_profile + " modscan --output=text --output-file=" + vars.outputdir + "\\MemInfo\\modscan.txt -f " + self.memfile, shell=True)
		print("Outputting SSDT")
		call("python " + vars.vol_dir + "\\vol.py --profile=" + self.image_profile + " ssdt --output=text --output-file=" + vars.outputdir + "\\MemInfo\\ssdt.txt -f " + self.memfile, shell=True)
		print("Outputting Driver Scan")
		call("python " + vars.vol_dir + "\\vol.py --profile=" + self.image_profile + " driverscan --output=text --output-file=" + vars.outputdir + "\\MemInfo\\driverscan.txt -f " + self.memfile, shell=True)
		print("Outputting File Scan")
		call("python " + vars.vol_dir + "\\vol.py --profile=" + self.image_profile + " filescan --output=text --output-file=" + vars.outputdir + "\\MemInfo\\filescan.txt -f " + self.memfile, shell=True)
		print("Outputting Mutant Scan")
		call("python " + vars.vol_dir + "\\vol.py --profile=" + self.image_profile + " mutantscan -s --output=text --output-file=" + vars.outputdir + "\\MemInfo\\mutantscan.txt -f " + self.memfile, shell=True)
		print("Outputting Thread Scan")
		call("python " + vars.vol_dir + "\\vol.py --profile=" + self.image_profile + " thrdscan --output=text --output-file=" + vars.outputdir + "\\MemInfo\\thrdscan.txt -f " + self.memfile, shell=True)
		print("Outputting Hive Scan")
		call("python " + vars.vol_dir + "\\vol.py --profile=" + self.image_profile + " hivescan --output=text --output-file=" + vars.outputdir + "\\MemInfo\\hivescan.txt -f " + self.memfile, shell=True)
		print("Outputting Hive List")
		call("python " + vars.vol_dir + "\\vol.py --profile=" + self.image_profile + " hivelist --output=text --output-file=" + vars.outputdir + "\\MemInfo\\hivelist.txt -f " + self.memfile, shell=True)
		# for pidnum in self.pidNumbers:
			# print("Outputting Files from PIDs")
			# call("python " + vars.vol_dir + "\\vol.py --profile=" + self.image_profile + " handles -p " + pidnum.replace("\n","").replace(".dmp","").replace(" ","") +" -t File --output=text --output-file=" + vars.outputdir + "\\MemInfo\\files-" + pidnum + ".txt -f " + self.memfile, shell=True)
			
	def evtparser(self):
		"""Runs evtparser or evtxparser and logparser against Log files"""
		path = vars.outputdir + "\\Logs"
		if vars.winver == "win7":
			try:
				call("mkdir " + path + "\\CSV", shell=True)
				print("PATH = " + path)
				for root, dir, files in os.walk(path):
					for file in files:
						logpath = os.path.join(root, file)
						fileName, fileExtension = os.path.splitext(file)
						print('files\\src\\tln\\evtxparse.exe -f "' + vars.outputdir + '\\Logs\\CSV\\' + fileName + '.csv" -t >> ' + vars.outputdir + "\\TLN\\log-events.txt")
						call('files\\src\\tln\\evtxparse.exe -f "' + vars.outputdir + '\\Logs\\CSV\\' + fileName + '.csv" -t >> ' + vars.outputdir + "\\TLN\\log-events.txt", shell=True)
			except:
				# log.logger.debug
				pass
		
		else:
			for root, dir, files in os.walk(path):
				for file in files:
					logpath = os.path.join(root, file)
					call('files\\src\\tln\\evtparse.exe -t -e ' + logpath + ' >> ' + vars.outputdir + "\\TLN\\log-events.txt", shell=True)
	def regparser(self):
		""" Runs RegTime against HIVES"""
		reg_names = ['NTUSER.DAT', 'SECURITY', 'SOFTWARE', 'SYSTEM', 'SAM', 'BCD-Template', 'COMPONENTS', 'DEFAULT']
		for root, dir, files in os.walk(vars.outputdir + '\\Registry'):
			for file in files:
				regpath = os.path.join(root, file)
				if file in reg_names:
					call('files\\src\\tln\\regtime.exe -s ' + vars.cname + ' -r ' + regpath + ' >> ' + vars.outputdir + '\\TLN\\reg-events.txt', shell=True)
					print('files\\src\\tln\\regtime.exe -s ' + vars.cname + ' -r ' + regpath + ' >> ' + vars.outputdir + '\\TLN\\reg-events.txt')

	def tlnparser(self):
		"""Runs bodyfile and Parse.exe against events file"""
		print('type '+ vars.outputdir + '\\TLN\\prefetch.txt >> ' + vars.outputdir + '\\TLN\\pref-events.txt')
		call('type '+ vars.outputdir + '\\TLN\\prefetch.txt >> ' + vars.outputdir + '\\TLN\\pref-events.txt', shell=True)
		# print("Running files\\src\\tln\\analyzeMFT.py -f " + vars.outputdir + "\\TLN\\mft.dat -o " + vars.outputdir + "\\TLN\\mft.output -b " + vars.outputdir + "\\TLN\\bodyfile.txt")
		# call('python files\\src\\tln\\analyzeMFT.py -f '+ vars.outputdir + '\\TLN\\mft.dat -o '+ vars.outputdir + '\\TLN\\mft.output -b '+ vars.outputdir + '\\TLN\\bodyfile.txt', shell=True)
		call('files\\src\\tln\\bodyfile.exe -s ' + vars.cname + ' -f '+ vars.outputdir + '\\TLN\\fls_bodyfile.txt >> ' + vars.outputdir + '\\TLN\\events.txt', shell=True)
		
		iefile = "index.dat"
		# raw_input("Press Enter to continue...")
		for root, dir, files in os.walk(vars.outputdir + '\\BrowserHistory'):
			for file in files:
				iepath = os.path.join(root, file)
				print('Indexing ' + iepath + '\n')
				print(file)
				if file == iefile:
					# raw_input("Press Enter to continue...")
					# print("files\\src\\tln\\pasco.exe \"" + iepath + "\" >> "+ vars.outputdir + "\\TLN\\indexdat.txt")
					# call("files\\src\\tln\\pasco.exe \"" + iepath + "\" >> "+ vars.outputdir + "\\TLN\\indexdat.txt", shell=True)
					print("files\\src\\tln\\urlcache.exe -f "+ iepath + " -s " + vars.cname + " -l >> "+ vars.outputdir + "\\TLN\\browser-events.txt")
					call("files\\src\\tln\\urlcache.exe -f "+ iepath + " -s " + vars.cname + " -l >> "+ vars.outputdir + "\\TLN\\browser-events.txt", shell=True)

		# Cat all individual TLN files into the events.txt
		print('type '+ vars.outputdir + '\\TLN\\reg-events.txt >> '+ vars.outputdir + '\\TLN\\events.txt')
		call('type '+ vars.outputdir + '\\TLN\\reg-events.txt >> '+ vars.outputdir + '\\TLN\\events.txt', shell=True)
		print('type '+ vars.outputdir + '\\TLN\\log-events.txt >> '+ vars.outputdir + '\\TLN\\events.txt')
		call('type '+ vars.outputdir + '\\TLN\\log-events.txt >> '+ vars.outputdir + '\\TLN\\events.txt', shell=True)
		print('type '+ vars.outputdir + '\\TLN\\pref-events.txt >> '+ vars.outputdir + '\\TLN\\events.txt')
		call('type '+ vars.outputdir + '\\TLN\\pref-events.txt >> '+ vars.outputdir + '\\TLN\\events.txt', shell=True)
		print('type '+ vars.outputdir + '\\TLN\\browser-events.txt >> '+ vars.outputdir + '\\TLN\\events.txt')
		call('type '+ vars.outputdir + '\\TLN\\browser-events.txt >> '+ vars.outputdir + '\\TLN\\events.txt', shell=True)

		print('files\\src\\tln\\parse.exe -f '+ vars.outputdir + '\\TLN\\events.txt -r ' + str(vars.abitback) + "-" + str(vars.today.strftime("%m/%d/%Y")) + ' > ' + vars.outputdir + '\\TLN\\timeline.txt')
		call('files\\src\\tln\\parse.exe -f '+ vars.outputdir + '\\TLN\\events.txt -r ' + str(vars.abitback) + "-" + str(vars.today.strftime("%m/%d/%Y")) + ' > ' + vars.outputdir + '\\TLN\\timeline.txt', shell=True)
		# raw_input("Press Enter to continue...")