#!/usr/bin/env python

import gaminmod
import os.path

#
# the type of events provided in the callbacks.
#
GAMChanged=1
GAMDeleted=2
GAMStartExecuting=3
GAMStopExecuting=4
GAMCreated=5
GAMMoved=6
GAMAcknowledge=7
GAMExists=8
GAMEndExist=9

#
# The Gamin Errno values
GAM_OK =     0
GAM_ARG=     1 # Bad arguments
GAM_FILE=    2 # Bad filename
GAM_CONNECT= 3 # Connection failure
GAM_AUTH=    4 # Authentication failure
GAM_MEM=     5 # Memory allocation
GAM_UNIMPLEM=6 # Unimplemented
GAM_INTR=    7 # Interrupted system call

def GaminErrno():
    return gaminmod.Errno()

def GaminErrmsg(err = None):
    if err == None:
	err = gaminmod.Errno()
    if err == GAM_ARG:
        msg = "bad argument error"
    elif err == GAM_FILE:
        msg = "filename error"
    elif err == GAM_CONNECT:
        msg = "connection error"
    elif err == GAM_AUTH:
        msg = "authentication error"
    elif err == GAM_MEM:
        msg = "memory allocation error"
    elif err == GAM_UNIMPLEM:
        msg = "unimplemented part error"
    elif err == GAM_INTR:
        msg = "interrupted system call"
    else:
        msg = ""
    return msg

class GaminException(Exception):
    def __init__(self, value):
        Exception.__init__(self)
	self.value = value
	self.errno = GaminErrno()

    def __str__(self):
        str = GaminErrmsg(self.errno)
	if str != "":
            return repr(self.value) + ': ' + str
        return repr(self.value)

class WatchMonitor:
    """This is a wrapper for a FAM connection. It uses a single connection
       to the gamin server, over a socket. Use get_fd() to get the file
       descriptor which allows to plug it in an usual event loop. The
       watch_directory(), watch_file() and stop_watch() are direct mapping
       to the FAM API. The event raised are also a direct mapping of the
       FAM API events."""

    class WatchObject:
	def __init__ (self, monitor, mon_no, path, dir, callback, data=None):
	    self.monitor = monitor
	    self.callback = callback
	    self.data = data
	    self.path = path
	    self.__mon_no = mon_no
	    if dir:
		ret = gaminmod.MonitorDirectory(self.__mon_no, path, self);
		if ret < 0:
		    raise(GaminException("Failed to monitor directory %s" %
					 (path)))
	    else:
		ret = gaminmod.MonitorFile(self.__mon_no, path, self);
		if ret < 0:
		    raise(GaminException("Failed to monitor file %s" %
					 (path)))
	    self.__req_no = ret

	def _internal_callback(self, path, event):
	    if self.data:
		self.callback (path, event, self.data)
	    else:
		self.callback (path, event)

	def cancel(self):
	    ret = gaminmod.MonitorCancel(self.__mon_no, self.__req_no);
	    if ret < 0:
		raise(GaminException("Failed to stop monitor on %s" %
				     (path)))
	    
    def __init__ (self):
        self.__no = gaminmod.MonitorConnect()
	if self.__no < 0:
	    raise(GaminException("Failed to connect to gam_server"))
	self.objects = {}
	self.__fd = gaminmod.GetFd(self.__no)
	if self.__fd < 0:
	    gaminmod.MonitorClose(self.__no)
	    raise(GaminException("Failed to get file descriptor"))

    def __del__ (self):
        self.disconnect()
    
    def __raise_disconnected():
	raise(GaminException("Already disconnected"))
        
    def disconnect(self):
        if (self.__no >= 0):
	    gaminmod.MonitorClose(self.__no)
	self.__no = -1;

    def watch_directory(self, directory, callback, data = None):
        if (self.__no < 0):
	    __raise_disconnected();
        directory = os.path.abspath(directory)
        if self.objects.has_key(directory):
	    raise(GaminException("Resource %s already monitored" % (directory)))

	# flush any data from the server to avoid deadlocks
	self.handle_events()
        obj = self.WatchObject(self, self.__no, directory, 1, callback, data)
	self.objects[directory] = obj
	return obj

    def watch_file(self, file, callback, data = None):
        if (self.__no < 0):
	    __raise_disconnected();
        file = os.path.abspath(file)
        if self.objects.has_key(file):
	    raise(GaminException("Resource %s already monitored" % (file)))

	# flush any data from the server to avoid deadlocks
	self.handle_events()
        obj = self.WatchObject(self, self.__no, file, 0, callback, data)
	self.objects[file] = obj
	return obj

    def stop_watch(self, path):
        if (self.__no < 0):
	    return
        path = os.path.abspath(path)
	try:
	    obj = self.objects[path]
	except:
	    raise(GaminException("Resource %s is not monitored" % (path)))
	del self.objects[path]
	obj.cancel()
	
    def get_fd(self):
        if (self.__no < 0):
	    __raise_disconnected();
        return self.__fd

    def event_pending(self):
        if (self.__no < 0):
	    __raise_disconnected();
        ret = gaminmod.EventPending(self.__no);
	if ret < 0:
	    raise(GaminException("Failed to check pending events"))
	return ret

    def handle_one_event(self):
        if (self.__no < 0):
	    __raise_disconnected();
        ret = gaminmod.ProcessOneEvent(self.__no);
	if ret < 0:
	    raise(GaminException("Failed to process one event"))
	return ret

    def handle_events(self):
        if (self.__no < 0):
	    __raise_disconnected();
        ret = gaminmod.ProcessEvents(self.__no);
	if ret < 0:
	    raise(GaminException("Failed to process events"))
	return ret

def run_unit_tests():
    def callback(path, event):
        print "Got callback: %s, %s" % (path, event)
    mon = WatchMonitor()
    print "watching current directory"
    mon.watch_directory(".", callback)
    import time
    time.sleep(1)
    print "fd: ", mon.get_fd()
    ret = mon.event_pending()
    print "pending: ", ret
    if ret > 0:
        ret = mon.handle_one_event()
	print "processed %d event" % (ret)
	ret = mon.handle_events()
	print "processed %d remaining events" % (ret)
    print "stop watching current directory"
    mon.stop_watch(".")
    print "disconnecting"
    del mon

if __name__ == '__main__':
    run_unit_tests()
