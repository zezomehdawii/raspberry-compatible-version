import hashlib
from netfilterqueue import NetfilterQueue
from scapy.all import *
import json
import os
from web3 import Web3
import logging
import getpass
import time
#from BlockChanger_settings_Web import audit

##############################################################################
##                                 Blockchain Info                          ##
try:
    os.system("clear")
    print("[*] Setting up web3 functions. Please wait...")
    blockchainNetworkIP = "HTTP://127.0.0.1:8545"
    web3 = Web3(Web3.HTTPProvider(blockchainNetworkIP))
    jsonArray = '[{"constant":false,"inputs":[{"internalType":"string","name":"_name","type":"string"}],"name":"Activate","outputs":[],"payable":false,"stateMutability":"nonpayable","type":"function"},{"constant":false,"inputs":[{"internalType":"address","name":"_addr","type":"address"},{"internalType":"string","name":"_name","type":"string"},{"internalType":"string","name":"_hash_id","type":"string"},{"internalType":"string","name":"_ip","type":"string"},{"internalType":"string","name":"_mac","type":"string"}],"name":"add_device","outputs":[],"payable":false,"stateMutability":"nonpayable","type":"function"},{"constant":true,"inputs":[{"internalType":"string","name":"_hash_id","type":"string"}],"name":"authFunc","outputs":[{"internalType":"bool","name":"","type":"bool"}],"payable":false,"stateMutability":"view","type":"function"},{"constant":true,"inputs":[],"name":"checkAdminIsLoggedIn","outputs":[{"internalType":"bool","name":"","type":"bool"}],"payable":false,"stateMutability":"view","type":"function"},{"constant":true,"inputs":[],"name":"checkIsAdded","outputs":[{"internalType":"bool","name":"","type":"bool"}],"payable":false,"stateMutability":"view","type":"function"},{"constant":false,"inputs":[{"internalType":"string","name":"_name","type":"string"}],"name":"deActivate","outputs":[],"payable":false,"stateMutability":"nonpayable","type":"function"},{"constant":true,"inputs":[{"internalType":"string","name":"_Name","type":"string"}],"name":"displayByName","outputs":[{"internalType":"address","name":"","type":"address"},{"internalType":"string","name":"","type":"string"},{"internalType":"string","name":"","type":"string"},{"internalType":"string","name":"","type":"string"},{"internalType":"string","name":"","type":"string"},{"internalType":"enum BlockChanger.State","name":"","type":"uint8"}],"payable":false,"stateMutability":"view","type":"function"},{"constant":true,"inputs":[{"internalType":"address","name":"_addr","type":"address"}],"name":"displayInfo","outputs":[{"internalType":"address","name":"","type":"address"},{"internalType":"string","name":"","type":"string"},{"internalType":"string","name":"","type":"string"},{"internalType":"string","name":"","type":"string"},{"internalType":"string","name":"","type":"string"},{"internalType":"enum BlockChanger.State","name":"","type":"uint8"}],"payable":false,"stateMutability":"view","type":"function"},{"constant":true,"inputs":[],"name":"getCount","outputs":[{"internalType":"uint256","name":"","type":"uint256"}],"payable":false,"stateMutability":"view","type":"function"},{"constant":false,"inputs":[{"internalType":"address","name":"_address","type":"address"},{"internalType":"string","name":"_username","type":"string"},{"internalType":"string","name":"_password","type":"string"}],"name":"loginUser","outputs":[],"payable":false,"stateMutability":"nonpayable","type":"function"},{"constant":false,"inputs":[],"name":"logout","outputs":[],"payable":false,"stateMutability":"nonpayable","type":"function"},{"constant":false,"inputs":[{"internalType":"address","name":"_address","type":"address"},{"internalType":"string","name":"_username","type":"string"},{"internalType":"string","name":"_password","type":"string"}],"name":"pushAdminInfo","outputs":[],"payable":false,"stateMutability":"nonpayable","type":"function"}]'
    abi = json.loads(jsonArray)
    contractAddress = "0xCfEB869F69431e42cdB54A4F4f105C19C080A601"
    address = web3.toChecksumAddress(contractAddress)
    contract = web3.eth.contract(address=address, abi=abi)
    web3.eth.defaultAccount = web3.eth.accounts[0] #choose transaction account
    print("[*] web3 is connected!\n---------------------------------------------------------------------------\n")
except:
    print ("Blockchain connection failed")
    logging.error('Blockchain connection failed')
    exit(0)
##                                                                          ##
##############################################################################


def addDevice(ip_src, mac_src):
    deviceCount = contract.functions.getCount().call()
    iplist = ""
    deviceID = ""
    deviceName = ""
    addr = ""
    with open("ip_list.txt","r") as fr:
         iplist = fr.read()
         with open("ip_list.txt","w") as fw:
             while True:
                 if ip_src not in iplist:
                     if len(iplist) == 0: 
                         iplist = iplist + ip_src 
                     else: 
                         iplist = iplist + "," + ip_src
                     fw.write(iplist)
                     addr = web3.eth.accounts[deviceCount+1] # return the new address
                     deviceName = input("Enter device Name: ") # get device name
                     deviceID = hashlib.md5((ip_src + mac_src + "saltValue").encode('utf-8')).hexdigest()# calculate the id
                     tx_hash = contract.functions.add_device(addr, deviceName, deviceID, ip_src, mac_src).transact() # store the id to the blockchain
                     web3.eth.waitForTransactionReceipt(tx_hash)
                     print ("\n****************\n<++ [ADDED!] ++>\n****************\n")
                     logging.critical(f"{deviceName} added to the blockchain!")
                     display_by_name(deviceName)
                 else: 
                     print(f"The connected device [{ip_src}] [{mac_src}] is already exists!")
                     return    
    reboot = input(" <++[NOTE!] ++>\nYou must reboot the BlockChanger in order to allow new settings to take action \nDo you want to reboot now? y/n: ")
    logging.info('BlockChanger rebooted to commint new device!')
    if reboot == "y": os.system("sudo reboot")
    #packet.drop()
    return

                    
def display_by_name(name):
    info = contract.functions.displayByName(name).call()
    deviceCount = contract.functions.getCount().call()    
    if info[1] == "":
        print("\n[*] This device does not exists!\n")
    else:
        if info[5] == 0: state = "Active"
        else: state = "Down"
        print(f"""Device {deviceCount}:
        Address: {info[0]}
        Name: {info[1]}
        ID: {info[2]}
        IP: {info[3]}
        MAC: {info[4]}
        State: {state}""")

def displayAll():
    deviceCount = contract.functions.getCount().call()
    #accounts = contract.functions.signed_addresses().call() 
    accounts = web3.eth.accounts
    if deviceCount == 0: print ("\n-----------------\nEmpty Blockchain!\n-----------------")
    count = 1
    for i in accounts[1:deviceCount+1]:  # for loop to display addresses from device mapping in the smart contract.
        info = contract.functions.displayInfo(i).call()
        if info[1] == "":
            print("\n[*] This device does not exists!\n")
        else:
            if info[5] == 0: state = "Active"
            else: state = "Down"
            print(f"""Device {count}:
            Address: {info[0]}
            Name: {info[1]}
            ID: {info[2]}
            IP: {info[3]}
            MAC: {info[4]}
            State: {state}""")
        count += 1
    print(f"Total number of devices: {deviceCount}")

dontRepeatIP =  []
def detect_IP_and_mac(packet):
     # store repeated the incoming ips
    pkt = IP(packet.get_payload()) #converts the raw packet to a scapy compatible string
    if IP in pkt and pkt[IP].src not in dontRepeatIP:
        ip_src = pkt[IP].src
        #mac_src = packet.get_hw() #function by nfqueue gives hex data
        mac_src = getmacbyip(str(ip_src)) #funtion by scapy
        dontRepeatIP.append(ip_src)
        if (mac_src != None):
           print ("\n[NOTE] the traffic on the network will be on hold while you are running this function!")
           print ("[*] press Ctrl + C to exit this function!")
           print ("[*] waiting for device to be connected!")
           print ("-----------------------------------------------------------------------------------------")
           print("\n****************************************************************")
           print (f"[*] Device Detected!: [{str(ip_src)}] [{mac_src}]")
           print("****************************************************************\n")
           choice = input(f"\n[*] Do you want to add the device to the Blockchain? y/n: ")
           print("\n")
           if choice == "y":
              addDevice(ip_src, mac_src)
           else: return
          #packet.drop()
          #print("[*] exiting...")  
          #exit(0)
        else: return    
    else: 
        print("[*] Looking for another device...")
    # add "else" here to throw an error if the packet is not an IP packet.
    

def detect_device():
    netmask = getNetmask()
    #os.system("sudo iptables -F")
    os.system(f"sudo iptables -I INPUT -s {netmask} -m state --state NEW,RELATED,ESTABLISHED -j NFQUEUE --queue-num 2")
    #os.system("sudo iptables -I INPUT -d 192.168.1.3 -m iprange --src-range 192.168.1.130-192.168.1.140 -j NFQUEUE --queue-num 2")
    addnfqueue = NetfilterQueue()
    addnfqueue.bind(2, detect_IP_and_mac)
    try:
        logging.info('Adding device function has been executed!')
        print("[*] Waiting for new connection...")        
        addnfqueue.run()
    except KeyboardInterrupt:
        #os.system("sudo iptables -D INPUT -d 192.168.1.3 -m iprange --src-range 192.168.1.130-192.168.1.140 -j NFQUEUE --queue-num 2")
        os.system(f"sudo iptables -D INPUT -s {netmask} -m state --state NEW,RELATED,ESTABLISHED -j NFQUEUE --queue-num 2")
        #logging('Exiting (Adding device funtion)')
        addnfqueue.unbind()
        print("\n[*] Exiting...")

def activate_device():
    logging.info('Activate device function has been executed!')
    print("\n[Note] if you do not know the exact name of the meant device, you can get it from display all devices ")
    name = input("Enter device name: ")
    contract.functions.Activate(name).transact()
    info = contract.functions.displayByName(name).call()
    if info[5] == 0:
        print (f"\n[*] {name} is activated!")
        logging.info(f"{name} has been activated!")
    else: print("[*] device is not activated!\n[*] The device name is not exists or entered wrong!")

def deactivate_device():
    logging.info('Activate device function has been executed!')
    print("\n[Note] if you do not know the id of the meant device, you can get it from display all devices")    
    name = input("Enter device name: ")
    contract.functions.deActivate(name).transact()
    info = contract.functions.displayByName(name).call()
    if info[5] == 1:
        print (f"\n[*] {name} is deactivated!")
        logging.info(f"{name} has been deactivated!")
    else: print("[*] device is not deactivated!\nSomething went wrong!")

def authlog():
    with open("audit.log","r") as f:
        content=f.read()
        print (content)
def audit():
    with open("audit.log","r") as f:
        content=f.read()
        print(content)

# code to get the host ip address and turn the last oct to 0 with netmask
def getNetmask(): #change the interface to the appropriate one 
    #interface = "eth0"
    IPAddress = os.popen('ip addr show eth0  | grep "\<inet\>" | awk \'{ print $2 }\' | awk -F "/" \'{ print $1 }\'').read().strip()
    netmask = IPAddress
    netmask = netmask[:netmask.rfind('.')+1] + '0' + "/24"
    #print (f"\n[*] network mask: {netmask}")
    return netmask

def _exit():
    contract.functions.logout().transact()
    os.system("sudo iptables -F")
    print("[*] Exiting...")
    print("\n------------\nCopyrights\n------------")
    print("""
[1] Ziyad Mehdawi => 2180007088@iau.edu.sa
[2] Ahmad Al-Hassar => 2180000308@iau.edu.sa
[3] Mohammed Mogaibel => 2180002943@iau.edu.sa
[4] Khalid Al-Mulhim => 2180001282@iau.edu.sa
[5] Abdullah Al-Qahtani => 2180000433@iau.edu.sa\n""")
    logging.info('Exiting BlockChanger Settings')
    exit(0)

def main():
    choice = ""
    while choice != 8:
        print("\n-----------------------------\n<++ BlockChanger Settings ++>\n-----------------------------")
        print("""
[1] Add new device
[2] Activate device
[3] Deactivate device
[4] Display device information by name
[5] Display all devices information
[6] Display authentication log file
[7] Display settings log file
[8] Exit.""")
        choice = int(input("\n[*] Choose number from the menu to proceed: "))
        if choice == 1:
            detect_device()
        elif choice == 2:
            activate_device()
        elif choice == 3:
            deactivate_device()
        elif choice == 4:
            deviceName = input("Enter device name: ")
            display_by_name(deviceName)
        elif choice == 5:
             displayAll()
        elif choice == 6:
             authlog()
        elif choice == 7:
            audit()
        elif choice == 8:
            _exit()
        else: print("[*] Wrong entry!")

def login():
    while(True):
        print("\n----------------------\n<++ [Login Page!] ++>\n----------------------\n")
        print ("""\n
[1] Open login page.
[2] First time? you need to create an admin user.
[3] Exit.""")
        choice = int(input("\n[*] Choose number from the menu to proceed: "))
        if(choice == 1 ):
            while (True):
                username = input("Please enter admin username: ")
                password = getpass.getpass(prompt="Please enter admin password (won't be echoed): ")
                print (username, password)
                if (contract.functions.checkIsAdded().call()):
                    contract.functions.loginUser(web3.eth.defaultAccount, username, password).transact()
                    if (contract.functions.checkAdminIsLoggedIn().call()):
                            print(f"[*] Logged in successfully as {username}!")
                            time.sleep(4)
                            os.system("clear")
                            main()
                    else:
                        print ("[*] incorrect username or password!")
                else:
                    print("\n[*] There is no admin user!")
                    break
        elif (choice == 2):
            if(contract.functions.checkIsAdded().call()):
                print("\n[*] There is already an admin user!")
            else:
                username = input("Enter username: ")
                password = input("Enter password: ")
                contract.functions.pushAdminInfo(web3.eth.defaultAccount,username,password).transact()
                print ("[*] Admin user is added!")
        elif (choice == 3):
            _exit()
        else:
            print("[*] Wrong entry!")

if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO,filename='settings.log', encoding='utf-8', format='%(asctime)s:%(levelname)s:%(message)s')
    login()
