#!/usr/bin/env python

import gamin
import time

def callback(path, event):
    print "Got callback: %s, %s" % (path, event)

mon = gamin.WatchMonitor()
mon.watch_directory(".", callback)
time.sleep(1)
ret = mon.event_pending()
if ret > 0:
    ret = mon.handle_one_event()
    ret = mon.handle_events()
mon.stop_watch(".")
del mon

