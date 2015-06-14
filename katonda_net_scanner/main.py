__author__ = 'daniel'


from katonda_net_scanner.ScannerOOP import SystemManager
import threading
from threading import *
#from threading import Thread
from time import sleep

import time

system_manager = SystemManager()

class NetScanner_Thread(threading.Thread):


    def run(self):
        system_manager.turn_system_on()


    def stop(self):
        system_manager.turn_system_off()




class test:
    def __init__(self):
        self._thread = NetScanner_Thread()


    def on(self):
        self._thread.start()
        #self._thread.join()

    def off(self):
        self._thread.stop()

class Manager(object):

    def __init__(self):
        self._test = test()


    def turn_system_on(self):
        self._test.on()
        return True


    def turn_system_off(self):
      self._test.off()
      return True


    def get_system_status(self):
        return system_manager.get_system_status()



    def get_hosts(self):
        return system_manager.get_hosts()


    def get_security_breaches(self):
        return system_manager.get_security_breaches()











