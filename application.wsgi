#!/usr/bin/python3.6

import logging
import sys
logging.basicConfig(stream=sys.stderr)
sys.path.insert(0, "/home/pi/github/doto/")
from doto import application
application.secret_key = "dougherty"
