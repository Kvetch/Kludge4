import tkFileDialog, time, os, subprocess, glob, datetime, thread, fnmatch, csv, sys, codecs
from Tkinter import *
from subprocess import *
from codecs import BOM_UTF8, BOM_UTF16_BE, BOM_UTF16_LE, BOM_UTF32_BE, BOM_UTF32_LE
import kludge_vars as vars
import kludge_logger as log

class Comparer(object):
	""" Comparer for Kludge"""
	def __init__(self):
		print("Starting Baseline Comparison")
		self.base_analyze()

	def fopen(self,fname):
		"""Open or Fail"""
		try:
			return open(fname, 'U')
		except IOError, detail:
			#continue
			# # log.logger.debug
			return fail("couldn't open " + fname + ": " + str(detail))

	def sortAndUniq(self,input):
		"""Iterate thru the list and if not already in output then add it, then sort"""
		output = []
		for x in input:
			if x not in output:
				output.append(x)
		output.sort()
		return output

	def list_difference(self,list1, list2):
		"""uses list1 as the reference, returns list of items not in list2"""
		diff_list = []
		for item in list1:
			if not item in list2:
				self.outputfile.writelines(str(item))
		self.outputfile.close()
		return diff_list

	def check_bom(self,data):
		"""Check for UTF-16 little endian files.  Stupid Windows"""
		return [encoding for bom, encoding in vars.BOMS if data.startswith(bom)]
		
	def base_analyze(self):
		"""Sets up the variables and junk for comparison"""
		call("mkdir " + vars.outputdir + "\\Comparison", shell=True)
		self.dlldiffpath = vars.outputdir + "\\Comparison\\dll-diff.csv"

		self.autorunsdiff = vars.outputdir + "\\Comparison\\autoruns-diff.csv"
		self.autoservicesdiff = vars.outputdir + "\\Comparison\\autosrvs-diff.csv"
		self.codecsdiff = vars.outputdir + "\\Comparison\\codecs-diff.csv"
		self.exaddonsdiff = vars.outputdir + "\\Comparison\\exaddons-diff.csv"
		self.ieaddonsdiff = vars.outputdir + "\\Comparison\\ieaddons-diff.csv"
		self.lsadiff = vars.outputdir + "\\Comparison\\lsa-diff.csv"
		self.knowndlldiff = vars.outputdir + "\\Comparison\\knowndll-diff.csv"
		self.netdiff = vars.outputdir + "\\Comparison\\net-diff.csv"
		self.servicesdiff = vars.outputdir + "\\Comparison\\services-diff.csv"
		self.startupdiff = vars.outputdir + "\\Comparison\\startup-diff.csv"
		self.comparecsvfiles = {"AutoRuns.csv": self.autorunsdiff, "AutoStart-Services.csv": self.autoservicesdiff, "Codecs.csv": self.codecsdiff, "Explorer-Addons.csv": self.exaddonsdiff, "IE-AddOns.csv": self.ieaddonsdiff, "LSA.csv": self.lsadiff, "Known-Dlls.csv": self.knowndlldiff, "Prot-Net.csv": self.netdiff, "Services.csv": self.servicesdiff, "Startup.csv": self.startupdiff}
		if vars.optlevel >= 2:
			self.dllcompare()
		test = 0
		debugit = open(vars.tmp_trgt_dir + "\\whattheheck.txt", 'ab')
		for key in self.comparecsvfiles.iterkeys():
			debugit.write(str(key) + "\n")
			debugit.write(str(key) + "\n")
			self.csvcompare(key)
			test =+ 1
			print(test)
		debugit.close()
	
	def dllcompare(self):
		"""The List Dlls output is in an ugly text form so it needs a little extra lovin"""
		dllbasefile = vars.base_dir + '\Procs\\ListDlls.txt'
		newdllfile = vars.outputdir + '\Procs\\ListDlls.txt'
		self.outputfile = open(self.dlldiffpath, 'ab')
		f1 = self.fopen(dllbasefile)
		file1 = f1.readlines(); f1.close()
		file1Arr = []
		for aLine in file1:
			if aLine.find(" 0x") > -1:
				dllFullEntry = []
				breakString1 = aLine.split("  ")
				dllFullEntry.append(breakString1[-1])
				dllFullEntry.append(breakString1[-2])
				file1Arr.append(dllFullEntry)
		removeDup1 = []
		removeDup1 = self.sortAndUniq(file1Arr)
		f2 = self.fopen(newdllfile)
		file2 = f2.readlines(); f2.close()
		file2Arr = []
		for aLine in file2:
			if aLine.find(" 0x") > -1:
				dllFullEntry = []
				breakString2 = aLine.split("  ")   
				dllFullEntry.append(breakString2[-1])
				dllFullEntry.append(breakString2[-2])
				file2Arr.append(dllFullEntry)
		removeDup2 = []
		removeDup2 = self.sortAndUniq(file2Arr)
		for entry2 in self.list_difference(removeDup2, removeDup1):
			print entry2
			self.outputfile.writelines(str(entry2))

	def csvcompare(self,file):
		"""Regular CSV comparer"""
		file = file
		basename = open(vars.base_dir + '\SysInfo\\computername.txt', 'r')
		basecname = basename.readline()
		basecname = basecname.replace(" ","").replace("\n","")
		output = self.comparecsvfiles.get(file)
		self.outputfile = open(output, 'ab')
		print(vars.base_dir + '\Procs\\' + file)
		print(vars.outputdir + '\Procs\\' + file)
		file1Arr = []
		bomfile = open(vars.base_dir + '\Procs\\' + file,'r').read(4)
		toggleVar =  self.check_bom(bomfile)
		if toggleVar:
			datafile = codecs.open(vars.base_dir + '\Procs\\' + file, 'rb', encoding='utf-16-le')
			file1 = iter(datafile)
			file1.next()
			print("Found a UTF-16-LE file \n")
		else:
			print "Not UTF-16 little endian"
			file1 = open(vars.base_dir + '\Procs\\' + file, 'rb')
		for row in file1:
			samenamerow = row.replace(basecname,vars.cname)
			file1Arr.append(samenamerow)
		file1.close()
		removeDup1 = []
		removeDup1 = self.sortAndUniq(file1Arr)
#########################################
		file2Arr = []
		bomfile = open(vars.outputdir + '\Procs\\' + file,'r').read(4)
		toggleVar =  self.check_bom(bomfile)
		if toggleVar:
			datafile = codecs.open(vars.outputdir + '\Procs\\' + file, 'rb', encoding='utf-16-le')
			file2 = iter(datafile)
			file2.next()
			print("Found a UTF-16-LE file \n")
		else:
			print "Not UTF-16 little endian"
			file2 = open(vars.outputdir + '\Procs\\' + file, 'rb')
		##### Print header of file2 into diff file ############
		count = 0
		for row in file2:
			print("DUDE")
			if count == 0:
				self.outputfile.writelines(str(row))
				count =+ 1
			file2Arr.append(row)
		file2.close()
		removeDup2 = []
		removeDup2 = self.sortAndUniq(file2Arr)
		print "What is in File2 that is not in File1"
		self.list_difference(removeDup2, removeDup1)