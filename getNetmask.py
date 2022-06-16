import netifaces as ni
import os

def getNetmask():
    IPAddress = ni.ifaddresses('wlan0')[ni.AF_INET][0]['addr']
    netmask = IPAddress
    netmask = netmask[:netmask.rfind('.')+1] + '0' + "/24"
    print (netmask)
    return netmask
#getNetmask()
def getNetmask2():
    IPAddress = os.popen('ip addr show wlan0 | grep "\<inet\>" | awk \'{ print $2 }\' | awk -F "/" \'{ print $1 }\'').read().strip()
    netmask = IPAddress
    netmask = netmask[:netmask.rfind('.')+1] + '0' + "/24"
    return netmask

getNetmask()
getNetmask2()