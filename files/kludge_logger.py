import logging
import sys
import kludge_vars as vars

class KludgeLogger():
	""" Kludge Logging"""
	def __init__(self):
		# create logger
		global logger
		logger = logging.getLogger('KludgeLog')
		logger.setLevel(logging.DEBUG)
		hdlr = logging.FileHandler('.\kludge-' + vars.timestmp + '.log')
			
		# create formatter
		formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')

		# add formatter to hdlr
		hdlr.setFormatter(formatter)

		# add hdlr to logger
		logger.addHandler(hdlr)
		logger.debug
		
if __name__ == '__main__':
	sys.exit(main())