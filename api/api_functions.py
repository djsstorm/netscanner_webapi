import os
import json
from django.http import HttpResponse
from katonda_net_scanner.main import Manager



class API(object):

    def __init__(self):
        self._manager = Manager()


    def power_on(self):

        print("power on called")
        return self._manager.turn_system_on()


    def power_off(self):
        print("power off called")
        return self._manager.turn_system_off()


    def get_system_status(self):
        print("get_system_status called")
        return self._manager.get_system_status()

    def get_system_health(self):
        print("get_system_health called")
        # static data (tmp for testing)
        sys_health = [{"1# CPU": "87%", "2# Memory": "21%", "3# Tasks": "276", "4# Overall": "Intense Usage"}]
        return json.dumps(sys_health, sort_keys=False) #sort=true sorts according to the first lettwers and not appearance


    def get_logger(self):
        print("get_logger called")
            # static data (tmp for testing)
        data = [
                {"Log #": "01",  "Log Date": "04062015",  "Log Time": "2345",  "Log details": "Breach  on port 8080", },
                {"Log #": "02",  "Log Date": "03052015",  "Log Time": "2245",  "Log details": "Breach  on port 80", },
                {"Log #": "03",  "Log Date": "04052015",  "Log Time": "2145",  "Log details": "Breach  on port 23", },
                {"Log #": "04",  "Log Date": "05052015",  "Log Time": "2015",  "Log details": "Breach  on port SSH", },
                {"Log #": "05",  "Log Date": "31052015",  "Log Time": "1927",  "Log details": "Breach  on port FTP", },
                {"Log #": "06",  "Log Date": "30052015",  "Log Time": "2354",  "Log details": "Breach  on port TFTP", },
                {"Log #": "07",  "Log Date": "24052015",  "Log Time": "2331",  "Log details": "Breach  on port 8080", },
                {"Log #": "08",  "Log Date": "15052015",  "Log Time": "2354",  "Log details": "Breach  on port RDP", },
                {"Log #": "09",  "Log Date": "17052015",  "Log Time": "2315",  "Log details": "Breach  on port 69", },
                {"Log #": "10",  "Log Date": "19052015",  "Log Time": "2313",  "Log details": "Breach  on port 3389", },
                ]

        return json.dumps(data, sort_keys=False)





    def get_hosts(self):
        print("get_hosts called")
        data = self._manager.get_hosts()
        # static data (tmp for testing)
        #data = [
        #        {"Host #": "1",  "Name": "serv1",  "IP": "192.168.1.1",  "OS_type": "windows", "FoundDate": "1/1/2015", "status": "1"},
        #        {"Host #": "2",  "Name": "serv2",  "IP": "192.168.1.2",  "OS_type": "linux", "FoundDate": "2/1/2015", "status": "2"},
        #        {"Host #": "3",  "Name": "serv3",  "IP": "192.168.1.3",  "OS_type": "windows", "FoundDate": "2/1/2015", "status": "3"},
        #        ]
        return json.dumps(data, sort_keys=False)



    def get_security_breaches(self):
        print("get_security_breachs called")
        data = self._manager.get_security_breaches()
        # static data (tmp for testing)
        #data = [
        #    {"ID": "1",  "Host": {"Host #": "1",  "Name": "serv1",  "IP": "192.168.1.1",  "OS_type": "windows", "FoundDate": "1/1/2015", "status": "1"},  "Ports": {"openPorts": ["21", "67", "89"]}},
        #    {"ID": "2",  "Host": {"Host #": "2",  "Name": "serv2",  "IP": "192.168.1.2",  "OS_type": "linux", "FoundDate": "2/1/2015", "status": "2"},  "Ports": {"openPorts": [69, 3389, 22]}},
        #    ]
        return json.dumps(data, sort_keys=False)

