#!/usr/bin/env python

__description__ = 'kludge.py - multiple common forensics tools kludged together into a hopefully automated way to process, parse and run the tools'
__author__ = 'Nick Baronian'
__version__ = '4.1.3'
__date__ = '2012-08-15'

# Author: Nick Baronian [nick <at> theinterw3bs [dot] com]
# Name: kludge.py
# Copyright (c) 2008 Nick Baronian. All rights reserved.
# This software is distributed under the Apache License 2.0
#

import tkFileDialog, time, os, subprocess, glob, datetime, thread, fnmatch, os, sys
from Tkinter import *
from subprocess import *
sys.path.append('files')
import kludge_gui as gui
import kludge_vars as vars

class Kludge:
	""" Kludge """
	def __init__(self):
		self = self
		self.main()
		
	def main(self):
		"""Start Da GUI"""
		gui.WhatThe()
		
		
		# root = Tk()
		# root.title("Kludge 4.0.0")
		# app = gui.Application(root)
		# root.mainloop()
		
		
Kludge()