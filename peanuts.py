#!/usr/bin/python
# installer .sh file for ease of use
# Mac last seen alerts (given with time frame, print out LAST SEEN: $Location, $LAT, $LONG, $RSSI)
# Have Node/AngularJS with gmapjs or ngmapsjs offline to parse the csv with multiple options for import. 

# TODO

#Add better monitor mode checks, error correction and GPS failure corrections

import argparse
from gps import *
import sys
import manuf
from scapy.all import *
import datetime
import logging
import threading
import collections
import os.path
from logging.handlers import RotatingFileHandler

PROBE_REQUEST_TYPE=0
PROBE_REQUEST_SUBTYPE=4
AP_BROADCAST_SUBTYPE=8

accessPoints = []
macAP = []

clients = []
macClient = []
uni = 0


Numclients = 0
Numap = 0
Currentloc = 0

NAME = 'Peanuts'
DESCRIPTION = "A New Version of Snoopy-NG, a command line tool for logging 802.11 probe request frames"
whmp = manuf.MacParser()

gpsd = None #seting the global variable

# Console colors
W  = '\033[0m'  # white (normal)
R  = '\033[31m' # red
G  = '\033[32m' # green
O  = '\033[33m' # orange<
B  = '\033[34m' # blue
P  = '\033[35m' # purple
C  = '\033[36m' # cyan
GR = '\033[37m' # gray
T  = '\033[93m' # tan

class GpsPoller(threading.Thread):
  def __init__(self):
    threading.Thread.__init__(self)
    global gpsd #bring it in scope
    gpsd = gps(mode=WATCH_ENABLE) #starting the stream of info
    self.current_value = None
    self.running = True #setting the thread running to true
 
  def run(self):
	global gpsd
	while gpsp.running:
		try:
			if gpsd.waiting(): #only True if data is available
				gpsd.next()
		except:
			print "GPSD Failed:"
			gpsd.close()
			sys.exit()

def LoggingOfData(output):
	# setup our rotating logger
	if os.path.isfile(output) == False:
	    f = open(output,'w')
	    f.write('Time, Device, MAC Address, Manufacture, SSID, Crypto, GPS, Location\n')
	    f.close()
	global logger 
	logger = logging.getLogger(NAME)
	logger.setLevel(logging.INFO)
	handler = RotatingFileHandler(output, maxBytes=10000000, backupCount=99999)
	logger.addHandler(handler)

def parse_args():
    parser = argparse.ArgumentParser(description=DESCRIPTION)

    parser.add_argument('-i', '--interface', help="capture interface")
    parser.add_argument('-o', '--output', default='out.log', help="logging output location")
    parser.add_argument('-d', '--delimiter', default=',', help="output field delimiter")
    parser.add_argument('-g', '--gpstrack', default=False, help="Enable/Disable GPS Tracking")
    parser.add_argument('-l', '--location', default='None', help="Location of survey")
    parser.add_argument('-a', '--access', default=False, help="Include AP's into the survey")

    return parser.parse_args()

def PacketHandler(pkt):
    if pkt.haslayer(Dot11):
        if pkt.type==PROBE_REQUEST_TYPE and pkt.subtype == PROBE_REQUEST_SUBTYPE:
            PrintPacketClient(pkt)
        if args.access:   
            if pkt.type==PROBE_REQUEST_TYPE and pkt.subtype == AP_BROADCAST_SUBTYPE:
                PrintPacketAP(pkt)
                

def PrintPacketAP(pkt):
    global Numap, Currentloc    
    ts = time.time()
    st = datetime.datetime.fromtimestamp(ts).strftime('%Y-%m-%d %H:%M')

    ssid_probe = pkt.info
    manufacture = str(whmp.get_manuf(pkt.addr2))
    mac = pkt.addr2
    
    gpsloc = ''
    crypto = ''
    cap = pkt.sprintf("{Dot11Beacon:%Dot11Beacon.cap%}"
                      "{Dot11ProbeResp:%Dot11ProbeResp.cap%}").split('+')
    if 'privacy' in cap:
        crypto = "Y"
    else:
        crypto = "N"

    if args.gpstrack:
        gpsloc = str(gpsd.fix.latitude) + ':' + str(gpsd.fix.longitude)

    # Logging info
    fields = []
    fields.append(st) # Log Time
    fields.append('AP') # Log Client or AP
    fields.append(mac) # Log Mac Address
    fields.append(manufacture) # Log Device Manufacture
    fields.append(ssid_probe) # Log SSID
    fields.append(crypto) # Log SSID
    fields.append(gpsloc) # Log GPS data
    fields.append(args.location) # Log GPS data
    ''' RSSI
    try:
        extra = pkt.notdecoded
    except:
        extra = None    
    if extra!=None:
        signal_strength = -(256-ord(extra[-4:-3]))
    else:
        signal_strength = -100
    '''
    # if AP ssid is not in clients and its not empty then print out, add  AP ssid and mac to lists
    if ssid_probe not in accessPoints and ssid_probe != "":
        accessPoints.append(ssid_probe)
        macAP.append(mac)
        print W+ '[' +R+ 'AP:' +C+ manufacture + W + '/' + B + mac +W+ '] [' +G+ 'SSID:' +W+ '] ' +O+ ssid_probe +W
        Numap += 1
    # if ssid is in clients but mac isnt seen before then print out and add the mac to the list
    elif ssid_probe in accessPoints and mac not in macAP:
        macAP.append(mac)
        print W+ '[' +R+ 'AP:' +C+ manufacture + W + '/' + B + mac +W+ '] [' +G+ 'SSID:' +W+ '] ' +O+ ssid_probe +W
        Numap += 1
    
    logger.info(args.delimiter.join(fields))

def PrintPacketClient(pkt):    
    global Numclients, Currentloc
    ts = time.time()
    st = datetime.datetime.fromtimestamp(ts).strftime('%Y-%m-%d %H:%M')

    ssid_probe = pkt.getlayer(Dot11ProbeReq).info
    manufacture = str(whmp.get_manuf(pkt.addr2))
    mac = pkt.addr2
    gpsloc = ''
    crypto = ''

    if args.gpstrack:
        gpsloc = str(gpsd.fix.latitude) + ':' + str(gpsd.fix.longitude)

    # Logging info
    fields = []
    fields.append(st) # Log Time
    fields.append('Client') # Log Client or AP
    fields.append(mac) # Log Mac Address
    fields.append(manufacture) # Log Device Manufacture
    fields.append(ssid_probe) # Log SSID
    fields.append(crypto) # Log SSID
    fields.append(gpsloc) # Log GPS data
    fields.append(args.location) # Log GPS data
    ''' RSSI
    try:
        extra = pkt.notdecoded
    except:
        extra = None	
    if extra!=None:
        signal_strength = -(256-ord(extra[-4:-3]))
      # fields.append(str(signal_strength)) # RSSI
    else:
        signal_strength = -100
      # fields.append(str(signal_strength)) # RSSI
    '''
    # if ssid is not in clients and its not empty then print out, add ssid and mac to lists
    if ssid_probe not in clients and ssid_probe != "":
        clients.append(ssid_probe)
        macClient.append(mac)
        print W+ '[' +R+ 'Client:' +C+ manufacture + W + '/' + B + mac +W+ '] [' +G+ 'SSID:' +W+ '] ' +O+ ssid_probe +W
    # if ssid is in clients but mac isnt seen before then print out and add the mac to the list
    elif ssid_probe in clients and mac not in macClient:
        macClient.append(mac)
        print W+ '[' +R+ 'Client:' +C+ manufacture + W + '/' + B + mac +W+ '] [' +G+ 'SSID:' +W+ '] ' +O+ ssid_probe +W
        Numclients += 1
    # if mac is not in the list and the probe has a broadcast (empty) then add mac to list
    elif mac not in macClient and ssid_probe == "":
        macClient.append(mac)
        print W+ '[' +R+ 'Client:' +C+ manufacture + W + '/' + B + mac +W+ '] New Client'
        Numclients += 1


    logger.info(args.delimiter.join(fields))

def getWirelessInterfacesList():
    networkInterfaces=[]        
    command = ["iwconfig"]
    process = subprocess.Popen(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    process.wait()
    (stdoutdata, stderrdata) = process.communicate();
    output = stdoutdata
    lines = output.splitlines()
    for line in lines:
            if(line.find("IEEE 802.11")!=-1):
                    networkInterfaces.append(line.split()[0])
    return networkInterfaces

def main(intf):
    print O + '''
    %s______                      _       
    | ___ \                    | |      
    | |_/ /__  __ _ _ __  _   _| |_ ___ 
    |  __/ _ \/ _` | '_ \| | | | __/ __|
    | | |  __/ (_| | | | | |_| | |_\__ \

    \_|  \___|\__,_|_| |_|\__,_|\__|___/
    %s
    %sRelease Date%s: 26/03/2017
    %sRelease Version%s: V.1.0
    %sCode%s: stuart@sensepost.com // @NoobieDog
    %sVisit%s:  www.sensepost.com // @sensepost
    ''' %(B,C,R,W,R,W,R,W,R,W)         
    print '['+G+'*'+W+'] Probe Investigator'
    print '['+G+'-----------------------------------------------------'+W+']'

    sniff(iface=intf, prn=PacketHandler, store=0)

if __name__=="__main__":
    args = parse_args()
    
    start = time.time()

    LoggingOfData(args.output)

    if not args.interface:
        intf = raw_input('['+G+'*'+W+'] Enter the Name of the interface to sniff: ')
        print ("\n")
    else:
        intf = args.interface

    if "mon" not in intf: #yes i know this doesnt work with ubuntu/mint at the mo...
        print '['+G+'*'+W+'] Setting Wireless card into Monitor Mode'
        if 'mon' not in getWirelessInterfacesList():
            #call(['airmon-ng', 'check', 'kill'], stdout=DN, stderr=DN)
            cmd = ['airmon-ng', 'start' ,intf]
            p = subprocess.Popen(cmd)
            p.wait()
        intf = intf + 'mon'
        #intf =  'mon0'

    if args.gpstrack:    
        gpsp = GpsPoller() # create the thread
        try:
            gpsp.start() # start it up
            main(intf)
        except (KeyboardInterrupt, SystemExit): #when you press ctrl+c
            print "\nKilling Thread..."
            gpsp.running = False
            gpsp.join() # wait for the thread to finish what it's doing
            sys.exit()
    else:
        try:
            main(intf)
        except (KeyboardInterrupt, SystemExit): #when you press ctrl+c
            print "\nKilling Thread..."
            sys.close()
            sys.exit()

print '\n \033[31m%d \033[0mClients | \033[33m%d \033[0mAPs' % (Numclients, Numap)
# awk '!seen[$0]++' pta.log > pta.csv
# Below code actually tidys the export and can import strait into other formats (maltego + mapping)
outfile = args.output + '.csv'
print G + '\n Creating CSV: ' + W + outfile
with open(args.output, 'rb') as inf, open(outfile, 'wb') as outf:
    outf.writelines(collections.OrderedDict.fromkeys(inf))
print G + '\n Elapsed Time: ' + W + '%s' % (time.time() - start)