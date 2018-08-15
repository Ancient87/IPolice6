#!/usr/bin/python

import sys
import configparser
import time
import pdb

if __name__ == "__main__":
	configfile = "configs/startup_config.conf"
	if len(sys.argv) > 1:
		configfile = sys.argv[1]

	parser = configparser.ConfigParser()
	conf = parser.parse_file(configfile)
	
	pdb.set_trace()
	conf.start()

	try:
		while 1:
			time.sleep(10)	

	except KeyboardInterrupt:
		print "Shutting down"
		conf.stop()
		conf.join()
		print "All threads done, closing main app"
		sys.exit(1)
