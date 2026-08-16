#!/usr/bin/env python3

import os
import shutil
import stat
import sys
from socrate import conf, system

system.set_env()

os.chmod("/var/lib/xapsd", mode=stat.S_IRWXU)
shutil.chown("/var/lib/xapsd", "mailu", "mailu")

conf.jinja("/xapsd.yaml", os.environ, "/etc/xapsd/xapsd.yaml")

system.drop_privs_to("mailu")

os.execv("/usr/sbin/xapsd", ["xapsd"])
