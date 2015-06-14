#!/usr/bin/env python
# -*- coding: utf-8 -*-


#import nmap
from katonda_net_scanner.nmap import nmap
import datetime
import sqlite3
from enum import Enum
#from libnmap.process import NmapProcess
from katonda_net_scanner.libnmap.process import NmapProcess
import xml.etree.ElementTree as ET
from abc import ABCMeta, abstractmethod
import uuid
from email.mime.text import MIMEText
from datetime import date
import smtplib
from collections import OrderedDict

class HostState(Enum):
    up = 1
    down = 2
    unknown = 3


class ScanManager:

    def __init__(self):
        self._nm = nmap.PortScanner()
        self._ports = []
        self._host = []

    @staticmethod
    def scan(host):

        scan_result = ScanResult()
        scan_result.host = host
        scan_result.id = str(uuid.uuid4().time)
        host.last_scanned = scan_result.id
        scan_result.timestamp = str(datetime.datetime.now())

        nmap_process = NmapProcess(targets=host.ip, options="-sV")
        nmap_process.run_background()

        print("<<<<<<<<<<<<<<<<<<<<<<<<<<<<< **  S T A R T I N G     S C A N  ** >>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>")

        while nmap_process.is_running():
            nmap_task = nmap_process.current_task
            if nmap_task:
                print("Task {0} ({1}): ETC: {2} DONE: {3}%".format(nmap_task.name,
                                                                   nmap_task.status,
                                                                   nmap_task.etc,
                                                                   nmap_task.progress))

        print("rc: {0} output: {1}".format(nmap_process.rc, nmap_process.summary))

        file = open('results.xml', 'w')
        file.write(nmap_process.stdout)
        file.close()

        tree = ET.parse('results.xml')
        root = tree.getroot()

        for portItr in root.iter('port'):
            scan_result.open_ports.append(portItr.get('portid'))

        print('----------------------------')
        print('hostname: ' + scan_result.host.name)
        print('host ip: ' + scan_result.host.ip)
        print('id:' + scan_result.id)
        print('ts:' + scan_result.timestamp)
        print('Open Ports: ' + str(scan_result.open_ports))
        print('----------------------------')

        return scan_result

    @property
    def ports(self):
        return self._ports

    @ports.setter
    def ports(self, ports):
        self._ports = ports

    @property
    def host(self):
        return self._host

    @host.setter
    def host(self, host):
        self._host = host


class Diff:
    def __init__(self, security_breach_table):
        self._nm = nmap.PortScanner()

        self._notificationManager = NotificationManager(security_breach_table)



    def calc_diff(self, scan_result1, scan_result2):

        if scan_result1 is None or scan_result2 is None:
            return None

        print("Comparing " + scan_result1.get_id() + " and " + scan_result2.get_id())

        compared_scan_results = ComparedScanResults(scan_result1, scan_result2)
        compared_scan_results._id = uuid.uuid4().time

        if scan_result1.open_ports == scan_result2.open_ports:
            print("No change")

            compared_scan_results.ports_were_close_now_open = None

        else:
            ports_were_close_now_open  = []
            temp_open_port_scan1 = scan_result1.open_ports
            temp_open_port_scan2 = scan_result2.open_ports

            for x in temp_open_port_scan2:
                if x not in temp_open_port_scan1:
                    ports_were_close_now_open.append(x)

            compared_scan_results._PortsWereCloseNowOpen = ports_were_close_now_open
            print("BREACH DETECTED!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!")
            self._notificationManager.notify_breach(scan_result2.host.ip, temp_open_port_scan2)


            temp_open_port_scan1 = scan_result1.open_ports
            temp_open_port_scan2 = scan_result2.open_ports

            for x in temp_open_port_scan2:
                if x in temp_open_port_scan1:
                    temp_open_port_scan1.remove(x)

            compared_scan_results._PortsWereOpenNowClose = temp_open_port_scan1

        return compared_scan_results


class Host:
    def __init__(self, ip='', mac_address='', name='', start_time='', end_time='', state=HostState.unknown, os_type='',
                 last_scanned=''):
        self._ip = ip
        self._mac_address = mac_address
        self._name = name
        self._start_time = start_time
        self._end_time = end_time
        self._state = state
        self._os_type = os_type
        self._last_scanned = last_scanned

    @property
    def last_scanned(self):
        return self._last_scanned

    @last_scanned.setter
    def last_scanned(self, last_scanned):
        self._last_scanned = last_scanned

    @property
    def ip(self):
        return self._ip

    @ip.setter
    def ip(self, ip):
        self._ip = ip

    @property
    def mac_address(self):
        return self._mac_address

    @mac_address.setter
    def mac_address(self, value):
        self._mac_address = value

    @property
    def name(self):
        return self._name

    @name.setter
    def name(self, name):
        self._name = name

    @property
    def start_time(self):
        return self._start_time

    @start_time.setter
    def start_time(self, value):
        self._start_time = value

    @property
    def end_time(self):
        return self._end_time

    @end_time.setter
    def end_time(self, value):
        self._end_time = value

    @property
    def state(self):
        return self._state

    @state.setter
    def state(self, state):
        self._state = state


class ScanResult:
    def __init__(self):
        self._id = None
        self._timestamp = None
        self._host = Host('127.0.0.1', 'localhost')
        self._openPorts = []
        self._closedPorts = []

    @property
    def id(self):
        return self._id

    @id.setter
    def id(self, value):
        self._id = value

    @property
    def timestamp(self):
        return self._timestamp

    @timestamp.setter
    def timestamp(self, value):
        self._timestamp = value

    @property
    def host(self):
        return self._host

    @host.setter
    def host(self, value):
        self._host = value

    @property
    def open_ports(self):
        return self._openPorts

    @open_ports.setter
    def open_ports(self, open_ports):
        self._openPorts = open_ports

    @property
    def closed_ports(self):
        return self._closedPorts

    @closed_ports.setter
    def closed_ports(self, value):
        self._closedPorts = value

    def get_id(self):
        return self._id

    def get_timestamp(self):
        return self._timestamp

    def get_host(self):
        return self._host


class ComparedScanResults:
    def __init__(self, scan1, scan2):
        self._scan1 = scan1
        self._scan2 = scan2
        self._id = None
        self._PortsWereOpenNowClose = []
        self._PortsWereCloseNowOpen = []

    @property
    def scan1(self):
        return self._scan1

    @scan1.setter
    def scan1(self, scan1):
        self._scan1 = scan1

    @property
    def scan2(self):
        return self._scan2

    @scan2.setter
    def scan2(self, scan2):
        self._scan2 = scan2

    @property
    def id(self):
        return self._id

    @id.setter
    def id(self, id):
        self._id = id

    @property
    def ports_were_close_now_open(self):
        return self._PortsWereCloseNowOpen

    @ports_were_close_now_open.setter
    def ports_were_close_now_open(self, open_ports):
        self._PortsWereCloseNowOpen = open_ports


class HostManager:
    def __init__(self):
        self._hosts = dict()

    def add_host(self, host):
        # self._hosts.append(host)
        self._hosts[host.ip] = host

    @staticmethod
    def find_hosts():
        print("Scanning for hosts on LAN...")

        nmap_process = NmapProcess(targets="127.0.0.1", options="-R")  # ARP scan
        nmap_process.run_background()

        while nmap_process.is_running():
            nmap_task = nmap_process.current_task
            if nmap_task:
                print("Task {0} ({1}): ETC: {2} DONE: {3}%".format(nmap_task.name,
                                                                   nmap_task.status,
                                                                   nmap_task.etc,
                                                                   nmap_task.progress))

        print("rc: {0} output: {1}".format(nmap_process.rc, nmap_process.summary))

        hosts = dict()
        file = open('hosts.xml', 'w')
        file.write(nmap_process.stdout)
        file.close()

        tree = ET.parse('hosts.xml')
        root = tree.getroot()

        for hostNode in root.findall('host'):
            host_start_time = hostNode.get('starttime')
            host_end_time = hostNode.get('endtime')
            host_status = hostNode.find('status')
            host_addresses = hostNode.findall('address')
            host_ip_address = host_addresses[0]

            host_state = host_status.get('state')
            if host_state == "up":
                host_ip = host_ip_address.get('addr')
                host_mac = 'unknown'
                if len(host_addresses) == 2:
                    host_mac_address = host_addresses[1]
                    host_mac = host_mac_address.get('addr')
                name = host_ip
                host_name = hostNode.find('./hostnames/hostname')
                if host_name is not None:
                    name = host_name.get('name')
                hosts[host_mac] = Host(host_ip, host_mac, name, host_start_time, host_end_time,
                                       HostState.up)

        for curr_host in hosts.values():
            print('----------------------------')
            print('start time: ' + curr_host.start_time)
            print('end time: ' + curr_host.end_time)
            print('hostname: ' + curr_host.name)
            print('host ip: ' + curr_host.ip)
            print('mac: ' + curr_host.mac_address)
            print('State: ' + curr_host.state.name)
            print('----------------------------')

        return hosts

    def update_hosts_status(self):
        hosts = self.find_hosts()
        self._hosts.update(hosts)

        for key, value in self._hosts.items():
            if key not in hosts:
                value.state = HostState.down
            print('----------------------------')
            print('start time: ' + value.start_time)
            print('end time: ' + value.end_time)
            print('hostname: ' + value.name)
            print('host ip: ' + value.ip)
            print('mac: ' + value.mac_address)
            print('State: ' + value.state.name)
            print('----------------------------')
        return self._hosts


class SecurityBreach:
    def __init__(self, host_id="", open_ports=[]):

        self.__host_id = host_id
        self.__id = None
        self.__openPorts = open_ports
        self.__timestamp = str(datetime.datetime.now())

    @property
    def id(self):
        return self.__id

    @id.setter
    def id(self, id):
        self.__id = id

    @property
    def host_id(self):
        return self.__host_id

    @host_id.setter
    def host_id(self, host_id):
        self.__host_id = host_id

    @property
    def open_ports(self):
        return self.__openPorts

    @open_ports.setter
    def open_ports(self, open_ports):
        self.__openPorts = open_ports

    @property
    def timestamp(self):
        return self.__timestamp

    @timestamp.setter
    def timestamp(self, timestamp):
        self.__timestamp = timestamp



class SecurityBreachManager():
    def __init__(self):
        self._discoveredNewSecurityBreach = []

    def check_for_security_breach(self):
        a = 1


class Util:
    @staticmethod
    def clean_db_result(column):
        temp = str(column).replace("(", "")
        column = str(temp).replace(")", "")
        temp = str(column).replace("'", "")
        column = str(temp).replace(",", "")

        return column


class AbsDb:
    __metaclass__ = ABCMeta

    def __init__(self, db_path):
        self._dbPath = db_path
        self._cursor = None
        self._conn = None

    @abstractmethod
    def create_table(self):
        raise NotImplementedError()

    def connect(self):
        try:

            self._conn = sqlite3.connect(self._dbPath, check_same_thread=False)
            self._cursor = self._conn.cursor()
            print("Connected to DB located in: ", self._dbPath)
        except sqlite3.DatabaseError:
            print("Unable to connect to DB")

    def disconnect(self):
        try:
            self._conn.close()
            print("Disconnected from DB")
        except sqlite3.DatabaseError:
            print("Unable to disconnect from DB")

    @abstractmethod
    def get(self, id):
        raise NotImplementedError()


class ScansTable(AbsDb):

    def __init__(self, db_path, ports_table):
        self._dbPath = db_path
        self.ports_table = ports_table
        self.ports_table.connect()

    def create_table(self):
        self.ports_table.create_table()
        self._cursor.execute('''CREATE TABLE IF NOT EXISTS scans
             (id text,host text,timestamp text)''')

        self._conn.commit()

    def insert(self, pid, phost, pts, open_ports):
        self._cursor.execute('INSERT INTO scans VALUES ('+'"'+pid+'"'+','+'"'+phost+'"'+','+'"'+pts+'"'+')')
        self._conn.commit()
        for port in open_ports:
            self.ports_table.insert(pid, port)
        self._conn.commit()

    def get(self, scan_id):
        try:
            sr = ScanResult()

            self._cursor.execute('SELECT host FROM scans WHERE id=' + scan_id)
            temp1 = self._cursor.fetchone()
            sr.get_host().ip = Util.clean_db_result(temp1)
            self._cursor.execute('SELECT timestamp FROM scans WHERE id=' + scan_id)
            temp1 = self._cursor.fetchone()

            sr._timestamp = Util.clean_db_result(temp1)
            sr._id = scan_id
            sr._openPorts = self.ports_table.get(scan_id)
        except:
            None
        return sr


class ComparedScansResultsTable(AbsDb):

    def __init__(self, db_path, ports_table):
        self._dbPath = db_path
        self.portsTable = ports_table

    def get(self, id):
        pass

    def create_table(self):
        self._cursor.execute('''CREATE TABLE IF NOT EXISTS ComparedScanResults
             (Id text,scan1 text, scan2 text)''')
       # self.portsTable.create_table()
        self._conn.commit()

    def insert(self, id, scan1, scan2, ports_was_close_now_open):
        try:
            self._cursor.execute('INSERT INTO ComparedScanResults VALUES ('+'"'+id+'"'+','+'"'+scan1.id+'"'+','+'"'+scan2.id+'"'+')')
            self._conn.commit()
            if ports_was_close_now_open is not None:
                for port in ports_was_close_now_open:
                    self.portsTable.insert(id, port)
                self._conn.commit()
        except sqlite3.DatabaseError:
            print("Unable to insert data")


class PortsTable(AbsDb):

    def get(self, scan_id):
        self._cursor.execute('SELECT port FROM ports WHERE scanId=' + scan_id)
        ports = self._cursor.fetchall()
        ports_list = []
        for port in ports:
            ports_list.append(Util.clean_db_result(port))
        return ports_list

    def create_table(self):
        self._cursor.execute('''CREATE TABLE IF NOT EXISTS ports
             (scanId text,port text)''')

        self._conn.commit()

    def insert(self, scan_id, port):
                self._cursor.execute('INSERT INTO ports VALUES ('+'"'+str(scan_id)+'"'+','+'"'+port+'"'+')')
                self._conn.commit()


class HostsTable(AbsDb):
    def get_by_ip(self, host_ip):

        temp_host = Host()
        single_host_array = []
        self._cursor.execute('SELECT * FROM hosts WHERE hostIp="'+host_ip+'"')
        row = self._cursor.fetchone()
        for col in row:
            Util.clean_db_result(col)
            single_host_array.append(col)
        temp_host.host_id = single_host_array[0]
        temp_host.ip = single_host_array[1]
        temp_host.mac_address = single_host_array[2]
        temp_host._name = single_host_array[3]
        temp_host.state = single_host_array[4]
        temp_host.os_type = single_host_array[5]
        temp_host.last_scanned = single_host_array[6]


        return temp_host



    def get_last_scan(self, host_ip):
        self._cursor.execute('SELECT lastScanned FROM hosts WHERE hostIp="'+host_ip+'"')
        last_scanned = self._cursor.fetchone()
        return Util.clean_db_result(last_scanned)

    """
    def get(self, host_id):

        self._cursor.execute('SELECT * FROM hosts WHERE host_id="'+host_id+'"')
        row = self._cursor.fetchone()
        temp_host = Host()
        host_row = []
        for col in row:
            Util.clean_db_result(col)
            host_row.append(col)
        temp_host.ip = host_row[0]
        temp_host.mac_address = host_row[1]
        temp_host.name = host_row[2]
        temp_host.start_time = host_row[3]
        temp_host.end_time = host_row[4]
        temp_host.state = host_row[5]
        temp_host.os_type = host_row[6]
        temp_host.last_scanned = host_row[7]

        return temp_host
        """
    def get_all(self):
        list_of_all_hosts = []
        temp_host = Host()
        self._cursor.execute('SELECT * FROM hosts')
        all_rows = self._cursor.fetchall()
        single_host_array = []
        for row in all_rows:
            for col in row:
                Util.clean_db_result(col)
                single_host_array.append(col)
            temp_host.hosts_id = single_host_array[0]
            temp_host.ip = single_host_array[1]
            temp_host.mac_address = single_host_array[2]
            temp_host._name = single_host_array[3]
            temp_host.state = single_host_array[4]
            temp_host.os_type = single_host_array[5]
            temp_host.last_scanned = single_host_array[6]

            list_of_all_hosts.append(temp_host)

        return list_of_all_hosts

    def create_table(self):
        self._cursor.execute('''CREATE TABLE IF NOT EXISTS hosts
             (hostId text,hostIp text,mac text,name text,state text,os text,lastScanned text)''')
        self._conn.commit()

    def insert(self, host_id, host_ip, host_mac , host_name, host_state, os, last_scan):
        try:
            self._cursor.execute('INSERT INTO hosts VALUES ('+'"'+str(host_id)+'"'+','+'"'+host_ip+'"'+','+'"'+host_mac+'"'+','+'"'+host_name+'"'+','+'"'+host_state+'"'+','+'"'+os+'"'+','+'"'+last_scan+'"'+')')
            self._conn.commit()
        except sqlite3.DatabaseError:
            print("Unable to insert data")

    def delete(self, host_ip):
        try:
            self._cursor.execute('DELETE FROM hosts WHERE hostIp="'+host_ip+'"')
            self._conn.commit()
        except:
            print(host_ip + " was not deleted!")


class NotificationManager:
    def __init__(self, security_breach_table):
        self._portsTable = PortsTable("db.db")
        self._securityBreachTable = security_breach_table

    def notify_breach(self, host_id, ports):
        sb = SecurityBreach(host_id, ports)
        sb.id = uuid.uuid4().time
        sb.open_ports = ports
        sb.host_id = host_id
        try:

            self._securityBreachTable.insert(sb.id, host_id, sb.timestamp)
        except sqlite3.Error:
            print("Notification Manager: FATAL DB ERROR")
        for port in ports:
            self._securityBreachTable.portsTable.insert(sb.id, port)
        self.alert(sb, "daniel.manor87@gmail.com")

    @staticmethod
    def send_email(user_name, password, subject, body, cc=None, bcc=None):
        if not bcc:
            bcc = []
        if not cc:
            cc = []

        smtp_server = 'smtp.gmail.com'
        smtp_port = 587
        smtp_username = user_name
        smtp_password = password

        # email_to - should be array of emails
        email_from = user_name
        to = [email_from]
        subject = subject

        # date_format = '%d/%m/%Y'
        email_space = ", "

        data = body

        msg = MIMEText(data)
        # msg['Subject'] = email_subject + " %s" % (date.today().strftime(date_format))
        msg['Subject'] = subject
        msg['To'] = email_space.join(to)
        msg['cc'] = email_space.join(cc)
        msg['From'] = email_from
        mail = smtplib.SMTP(smtp_server, smtp_port)
        mail.starttls()
        mail.login(smtp_username, smtp_password)
        mail.sendmail(email_from, to + bcc, msg.as_string())
        mail.quit()
        print("Email Sent")

    @staticmethod
    def alert(breach):
        user_name = "katonda.netscanner@gmail.com"
        password = "katonda123"
        subject = "Breach detected in host"
        host = breach.host

        body = "Host details:\n" + \
               "Hostname: " + host.name + "\n" + \
               "IP: " + host.ip + "\n" + \
               "MAC Address: " + host.mac_address + "\n\n" + \
               "Our last scan on " + host.end_time + " detected new open ports:\n"

        for open_port in breach.open_ports:
            body += open_port + "\n"

        NotificationManager.send_email(user_name, password, subject, body)

class SecurityBreachTable(AbsDb):
    def __init__(self, db_path, ports_table):
        self.portsTable = ports_table
        self._dbPath = db_path

    def create_table(self):
        self.portsTable.create_table()
        self._cursor.execute('''CREATE TABLE IF NOT EXISTS SecurityBreach
             (BreachId text, HostId text, timestamp text)''')
        self._conn.commit()

    def insert(self, breach_id, host_id, timestamp):
        self._cursor.execute('INSERT INTO SecurityBreach '
                             'VALUES ('+'"'+str(breach_id)+'"'+','+'"'+str(host_id)+'"'+','+'"'+timestamp+'"'+')')
        self._conn.commit()

    def get(self, breach_id):

        self._cursor.execute('SELECT * FROM SecurityBreach WHERE BreachId="'+breach_id+'"')
        row = self._cursor.fetchone()
        temp_breach = SecurityBreach()
        breach = []
        for col in row:
            Util.clean_db_result(col)
            breach.append(col)
        temp_breach.id = breach[0]
        temp_breach.host_id = breach[1]
        temp_breach.timestamp = breach[2]
        temp_breach.open_ports = self.portsTable.get(temp_breach.id)
        return temp_breach

    def get_all(self):
        breaches = []
        self._cursor.execute('SELECT * FROM SecurityBreach')
        all_rows = self._cursor.fetchall()
        for row in all_rows:
            breach_row = []
            for col in row:
                Util.clean_db_result(col)
                breach_row.append(col)

            temp_breach = SecurityBreach()
            temp_breach.id = breach_row[0]
            temp_breach.host_id = breach_row[1]
            temp_breach.timestamp = breach_row[2]
            temp_breach.open_ports = self.portsTable.get(temp_breach.id)
            breaches.append(temp_breach)

        return breaches

class SystemManager:
    def __init__(self):
        self._hostManager = HostManager()
        self._hosts = None
        self.ports_table = PortsTable("db.db")
        self.hosts_table = HostsTable("db.db")
        self.scans_table = ScansTable("db.db", self.ports_table)
        self.compared_scans_results_table = ComparedScansResultsTable("db.db", self.ports_table)
        self.securityBreachTable = SecurityBreachTable("db.db", self.ports_table)
        self.scans_table.connect()
        self.hosts_table.connect()
        self.securityBreachTable.connect()
        self.securityBreachTable.create_table()
        self.compared_scans_results_table.connect()
        self.ports_table.connect()
        self.hosts_table.create_table()
        self.scans_table.create_table()
        self.ports_table.create_table()
        self.compared_scans_results_table.create_table()
        self.scan_manager = ScanManager()
        self._run = False


    def get_updated_hosts(self):
        self._hosts = self._hostManager.update_hosts_status()
        return self._hosts


    def turn_system_on(self):
        first_run = True
        while self._run:
            if first_run:
                print(" ++++++++++++ >>>>>>> Katonda  NetScanner <<<<<<< ++++++++++++")

                if not self._run:
                    break

                hosts = self._hostManager.find_hosts()

                if not self._run:
                    break

                self.scan_compare_discovered_hosts(hosts)
                first_run = False
            else:
                if not self._run:
                    break

                hosts = self.get_updated_hosts()

                if not self._run:
                    break

                self.scan_compare_discovered_hosts(hosts)

                if not self._run:
                    break

                self.hosts_table.get_all()
            if not self._run:
                self.scans_table.disconnect()
                print(" ++++++++++++ >>>>>>> Katonda halted! <<<<<<< ++++++++++++")

    def turn_system_off(self):
            #print("Halting!!!!!!!!")
            self._run = False
      #  self.scans_table.disconnect()

        # def insert_hosts_to_db(self):
        # self._hostsTable.insert(self._hosts[])

    def scan_compare_discovered_hosts(self, hosts):

        # scanning each host and adding reference from host to latest scan
        print("Scanning discovered hosts")
        d = Diff(self.securityBreachTable)
        for k, v in hosts.items():
            temp_host = v
            scan_result = self.scan_manager.scan(temp_host)
            try:
                compared_scan_result = Diff.calc_diff(d, self.scans_table.get(self.hosts_table.get_last_scan(temp_host.ip)), scan_result)
            except Exception as inst:
                compared_scan_result = None
                print(inst)

            # inserting scans comparision results to db
            if compared_scan_result is not None:
                self.compared_scans_results_table.insert(str(compared_scan_result.id), compared_scan_result.scan1, compared_scan_result.scan2, compared_scan_result.ports_were_close_now_open)
            # deleting old host
            self.hosts_table.delete(temp_host.ip)
            self.hosts_table.insert(uuid.uuid4().time, temp_host.ip, str(temp_host.mac_address) ,temp_host._name, str(temp_host.state), temp_host._os_type,temp_host.last_scanned)
            # updating scans table
            self.scans_table.insert(scan_result.id, scan_result.host.ip, scan_result.timestamp, scan_result.open_ports)

    def get_system_status(self):
        return self._run


    def get_hosts(self):
        hosts_list = self.hosts_table.get_all()
        hosts = []
        host_dict = OrderedDict()

        for host in hosts_list:
            host_dict["Host_id"] = host.hosts_id
            host_dict["Name"] = host.name
            host_dict["IP"] = host.ip
            host_dict["OS_type"] = host.os_type
            host_dict["FoundDate"] = host.end_time
            host_dict["Status"] = host.state
            hosts.append(host_dict)

        return hosts

    def get_host(self,host_id):
        tmp_host = self.hosts_table.get(host_id)
        hosts = []
        host_dict = OrderedDict()
        host_dict["Host_id"] = tmp_host.id
        host_dict["Name"] = tmp_host.name
        host_dict["IP"] = tmp_host.ip
        host_dict["OS_type"] = tmp_host.os_type
        host_dict["FoundDate"] = tmp_host.end_time
        host_dict["Status"] = tmp_host.state
        hosts.append(host_dict)

        return hosts


    def get_security_breaches(self):

        breaches_list = self.securityBreachTable.get_all()
        breaches = []
        #breach_dict = dict()
        breach_dict=OrderedDict()
        for breach in breaches_list:

            breach_dict["ID"] = breach.id

            """
            tmp_host = self.hosts_table.get_by_ip(breach.host_id)
            host_dict = dict()
            host_dict["Host_id"] = tmp_host.host_id
            host_dict["Name"] = tmp_host.name
            host_dict["IP"] = tmp_host.ip
            host_dict["OS_type"] = tmp_host.os_type
            host_dict["FoundDate"] = tmp_host.end_time
            host_dict["Status"] = tmp_host.state
            breach_dict["Host"] = host_dict
            """
            breach_dict["Host_id"] = breach.host_id

            breach_dict["FoundDate"] = breach.timestamp
            breach_dict["OpenPorts"] = breach.open_ports

            breaches.append(breach_dict)

        return breaches
