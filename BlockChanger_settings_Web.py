#from flask import *
from flask import Flask, redirect, url_for, render_template, request, session, flash, jsonify
from datetime import timedelta
import hashlib
from netfilterqueue import NetfilterQueue
from responses import Response
from scapy.all import *
import json
import os
from web3 import Web3
import logging

#-----------------------SECRET KEY-------------------------
app = Flask(__name__)
app.secret_key = "M7NK"
app.permanent_session_lifetime = timedelta(days=5)
#------------------------------------------------------------

##############################################################################
##                                 Blockchain Info                          ##
try:
    web3 = Web3(Web3.HTTPProvider(blockchainNetworkIP))
    jsonArray = '[{"constant":false,"inputs":[{"internalType":"string","name":"_name","type":"string"}],"name":"Activate","outputs":[],"payable":false,"stateMutability":"nonpayable","type":"function"},{"constant":false,"inputs":[{"internalType":"address","name":"_addr","type":"address"},{"internalType":"string","name":"_name","type":"string"},{"internalType":"string","name":"_hash_id","type":"string"},{"internalType":"string","name":"_ip","type":"string"},{"internalType":"string","name":"_mac","type":"string"}],"name":"add_device","outputs":[],"payable":false,"stateMutability":"nonpayable","type":"function"},{"constant":true,"inputs":[{"internalType":"string","name":"_hash_id","type":"string"}],"name":"authFunc","outputs":[{"internalType":"bool","name":"","type":"bool"}],"payable":false,"stateMutability":"view","type":"function"},{"constant":false,"inputs":[{"internalType":"string","name":"_name","type":"string"}],"name":"deActivate","outputs":[],"payable":false,"stateMutability":"nonpayable","type":"function"},{"constant":true,"inputs":[{"internalType":"string","name":"_Name","type":"string"}],"name":"displayByName","outputs":[{"internalType":"address","name":"","type":"address"},{"internalType":"string","name":"","type":"string"},{"internalType":"string","name":"","type":"string"},{"internalType":"string","name":"","type":"string"},{"internalType":"string","name":"","type":"string"},{"internalType":"enum BlockChanger.State","name":"","type":"uint8"}],"payable":false,"stateMutability":"view","type":"function"},{"constant":true,"inputs":[{"internalType":"address","name":"_addr","type":"address"}],"name":"displayInfo","outputs":[{"internalType":"address","name":"","type":"address"},{"internalType":"string","name":"","type":"string"},{"internalType":"string","name":"","type":"string"},{"internalType":"string","name":"","type":"string"},{"internalType":"string","name":"","type":"string"},{"internalType":"enum BlockChanger.State","name":"","type":"uint8"}],"payable":false,"stateMutability":"view","type":"function"},{"constant":true,"inputs":[],"name":"getCount","outputs":[{"internalType":"uint256","name":"","type":"uint256"}],"payable":false,"stateMutability":"view","type":"function"}]'
    abi = json.loads(jsonArray)
    contractAddress = "0x3B5D3C84d2DDe58BaaBd4737FD78CcAE38b9244E"
    address = web3.toChecksumAddress(contractAddress)
    contract = web3.eth.contract(address=address, abi=abi)
    web3.eth.defaultAccount = web3.eth.accounts[0] #choose transaction account
except:
    logging.error('Blockchain connection failed')
##                                                                          ##
##############################################################################


@app.route("/")
def home():
    return render_template("index.html")

@app.route("/login", methods=["POST", "GET"])
def login():
    if request.method == "POST":
        session.permanent = True
        user= request.form["user"]
        session["user"] = user
        flash(f"Login sucess, {user}") #POP UP  
        return redirect(url_for("user"))
    else:
        if "user" in session:
            flash("already logged 7ge")
            return redirect(url_for("user"))
        return render_template("login.html")

@app.route("/user") 
def user():
    if "user" in session:
        user = session["user"]
        return render_template("user.html", user=user)
    
    else:
        return redirect(url_for("login"))


@app.route("/logout")
def logout():
    if "user" in session:
        user = session["user"]
        flash(f"logging out, {user}", "info")
    session.pop("user", None)
    return redirect(url_for("login"))


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
                    #deviceName = input("Enter device Name: ") # get device name
                    deviceID = hashlib.md5((ip_src + mac_src + "saltValue").encode('utf-8')).hexdigest()# calculate the id
                    deviceName = request.form.get("new_ip")
                    tx_hash = contract.functions.add_device(addr, deviceName, deviceID, ip_src, mac_src).transact() # store the id to the blockchain
                    web3.eth.waitForTransactionReceipt(tx_hash)
                    flash("The IP: "+ deviceName +" was added successfully! \nYou must reboot the BlockChanger in order to allow new settings to take action")
                    #print ("\n----------------\n<++ [ADDED!] ++>\n----------------\n")
                    logging.critical(f"{deviceName} added to the blockchain!")
                    display_by_name(deviceName)
                    #return redirect(request.url)
                    return render_template("add_device.html", ip=ip_src, mac=mac_src)
                    #reboot = input(" <++[NOTE!] ++>\nYou must reboot the BlockChanger in order to allow new settings to take action \nDo you want to reboot now? y/n: ")
                    #logging.info('BlockChanger rebooted to commint new device!')
                    #if reboot == "y": os.system("sudo reboot")
                    #packet.drop()
                    #return
                else:
                    flash(f"The connected device [{ip_src}] [{mac_src}] is already exists!") 
                    #print(f"The connected device [{ip_src}] [{mac_src}] is already exists!")
                    return redirect(request.url)



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

@app.route("/displayall", methods=["POST","GET"]) 
def displayAll():
    if request.method == "POST":
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
    else:
        return render_template("/displayall.html")             

@app.route("/settings", methods=["POST","GET"])
def settings():
        if request.method == "GET":
            return render_template("settings.html")

@app.route("/audit", methods=["POST","GET"])
def audit():
        if request.method == "GET":
            with open("settings.log","r") as f:
                content=f.read()
            return render_template("audit.html", content=content)
        else:
            return render_template("audit.html")

@app.route("/auditlog", methods=["POST","GET"])
def authlog():
        if request.method == "GET":
            with open("audit.log","r") as f:
                content=f.read()
            return render_template("authlog.html", content=content)
        else:
            return render_template("authlog.html")

@app.route("/pihole", methods=["POST","GET"])
def pihole():
        if request.method == "GET":
            return render_template("pihole.html")

@app.route("/homeassis", methods=["POST","GET"])
def homeassis():
        if request.method == "GET":
            return render_template("homeassis.html")

dontRepeatIP =  []
def detect_IP_and_mac(packet):
    # store repeated the incoming ips
    pkt = IP(packet.get_payload()) #converts the raw packet to a scapy compatible string
    if IP in pkt and pkt[IP].src not in dontRepeatIP:
        ip_src = pkt[IP].src
        #mac_src = packet.get_hw() #function by nfqueue gives hex data
        mac_src = getmacbyip(str(ip_src)) #funtion by scapy
        dontRepeatIP.append(ip_src)
        return render_template("add_device.html", ip = ip_src, mac = mac_src)
        # print("\n****************************************************************")
        # print (f"[*] Device Detected!: [{str(ip_src)}] [{mac_src}]")
        # print("****************************************************************\n")
        # choice = input(f"\n[*] Do you want to add the device to the Blockchain? y/n: ")
        # print("\n")
        # if choice == "y":
        # addDevice(ip_src, mac_src)
        # else: return
        #packet.drop()
        #print("[*] exiting...")  
        #exit(0)
    else:
        pass
        # print("[*] looking for another device...")
    # add "else" here to throw an error if the packet is not an IP packet.
    

@app.route("/add_device", methods =["POST", "GET"])
def detect_device():
    if request.method == "GET":
        #netmask = getNetmask()
        #os.system("sudo iptables -F")
        #os.system(f"sudo iptables -I INPUT -s {netmask} -m state --state NEW,RELATED,ESTABLISHED -j NFQUEUE --queue-num 4")
        #addnfqueue = NetfilterQueue()
        #addnfqueue.bind(4, detect_IP_and_mac)
        try:
            # print ("\n[NOTE] the traffic on the network will be on hold while you are running this function!")
            # print ("[*] press Ctrl + C to exit this function!")
            # print ("[*] waiting for device to be connected!")
            # print ("-----------------------------------------------------------------------------------------")
            logging.info('Adding device function has been executed!')
            #addnfqueue.run()
            
        except KeyboardInterrupt:
            os.system("sudo iptables -F")
            addnfqueue.unbind()
            logging('Exiting (Adding device funtion)')
            print("\n[*] exiting...")
    else:
        return render_template("add_device.html")

@app.route("/activate_device", methods=["POST","GET"])
def activate_device():
    if request.method == "POST":
        logging.info('Activate device function has been executed!')
        # print("\n[Note] if you do not know the exact name of the meant device, you can get it from display all devices ")
        name = request.form.get("device_name")
        #name = input("Enter device name: ")
        contract.functions.Activate(name).transact()
        info = contract.functions.displayByName(name).call()
        if info[5] == 0:
            flash(f"\n[*] {name} is activated!")
            #print (f"\n[*] {name} is activated!")
            logging.critical(f"{name} has been activated!")
            return redirect(request.url)
        else:
            flash(f"device is not activated!\n[*] The device name is not exists or entered wrong!")
            #print("[*] device is not activated!\n[*] The device name is not exists or entered wrong!")
            return redirect(request.url)
    else:
        return render_template("/activate_device.html")


@app.route("/deactivate_device", methods=["POST","GET"])
def deactivate_device():
    if request.method == "POST":
        logging.info('Activate device function has been executed!')
        #print("\n[Note] if you do not know the id of the meant device, you can get it from display all devices")    
        #name = input("Enter device name: ")
        name = request.form.get("device_name")
        contract.functions.deActivate(name).transact()
        info = contract.functions.displayByName(name).call()
        if info[5] == 1:
            flash(f"{name} is deactivated!")
            #print (f"\n[*] {name} is deactivated!")
            logging.critical(f"{name} has been deactivated!")
            return redirect(request.url)
        else: 
            flash(f"device is not deactivated!\n[*] The device name is not exists or entered wrong!")
            # print("[*] device is not deactivated!\nSomething went wrong!")
            return redirect(request.url)
    else: 
        return render_template("/deactivate_device.html")

# code to get the host ip address and turn the last oct to 0 with netmask
def getNetmask(): #change the interface to the appropriate one 
    #interface = "eth0"
    IPAddress = os.popen('ip addr show wlan0  | grep "\<inet\>" | awk \'{ print $2 }\' | awk -F "/" \'{ print $1 }\'').read().strip()
    netmask = IPAddress
    netmask = netmask[:netmask.rfind('.')+1] + '0' + "/24"
    #print (f"\n[*] network mask: {netmask}")
    return netmask

def _exit():
    os.system("sudo iptables -F")
    print("Exiting...")
    logging.info('Exiting BlockChanger Settings')
    exit(0)

def main():
    choice = ""
    while choice != 6:
        print("\n-----------------------------\n<++ BlockChanger Settings ++>\n-----------------------------")
        print("""
[1] Add new device
[2] Activate device
[3] Deactivate device
[4] Display device information by name
[5] Display all devices information
[6] Exit.""")
        choice = int(input("\n[*] Choose number from the menu to proceed: "))
        if choice == 1:
            detect_device()
        elif choice == 2:
            activate_device()
        elif choice == 3:
            deactivate_device()
        elif choice == 4:
            deviceName = input("enter device name: ")
            display_by_name(deviceName)
        elif choice == 5:
             displayAll()
        elif choice == 6:
            _exit()
        else: print("Wrong entry!")


if __name__ == "__main__":
    app.run(debug=True)
    logging.basicConfig(level=logging.INFO,filename='settings.log', encoding='utf-8', format='%(asctime)s:%(levelname)s:%(message)s')
    #main()
