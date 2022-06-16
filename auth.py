import hashlib
from netfilterqueue import NetfilterQueue
from scapy.all import *
import json
from web3 import Web3
import logging



##############################################################
##                      Blockchain Info                     ##


blockchainNetworkIP = "http://127.0.0.1:8545"
web3 = Web3(Web3.HTTPProvider(blockchainNetworkIP))
jsonArray = '[{"constant":false,"inputs":[{"internalType":"string","name":"_name","type":"string"}],"name":"Activate","outputs":[],"payable":false,"stateMutability":"nonpayable","type":"function"},{"constant":false,"inputs":[{"internalType":"address","name":"_addr","type":"address"},{"internalType":"string","name":"_name","type":"string"},{"internalType":"string","name":"_hash_id","type":"string"},{"internalType":"string","name":"_ip","type":"string"},{"internalType":"string","name":"_mac","type":"string"}],"name":"add_device","outputs":[],"payable":false,"stateMutability":"nonpayable","type":"function"},{"constant":true,"inputs":[{"internalType":"string","name":"_hash_id","type":"string"}],"name":"authFunc","outputs":[{"internalType":"bool","name":"","type":"bool"}],"payable":false,"stateMutability":"view","type":"function"},{"constant":true,"inputs":[],"name":"checkAdminIsLoggedIn","outputs":[{"internalType":"bool","name":"","type":"bool"}],"payable":false,"stateMutability":"view","type":"function"},{"constant":true,"inputs":[],"name":"checkIsAdded","outputs":[{"internalType":"bool","name":"","type":"bool"}],"payable":false,"stateMutability":"view","type":"function"},{"constant":false,"inputs":[{"internalType":"string","name":"_name","type":"string"}],"name":"deActivate","outputs":[],"payable":false,"stateMutability":"nonpayable","type":"function"},{"constant":true,"inputs":[{"internalType":"string","name":"_Name","type":"string"}],"name":"displayByName","outputs":[{"internalType":"address","name":"","type":"address"},{"internalType":"string","name":"","type":"string"},{"internalType":"string","name":"","type":"string"},{"internalType":"string","name":"","type":"string"},{"internalType":"string","name":"","type":"string"},{"internalType":"enum BlockChanger.State","name":"","type":"uint8"}],"payable":false,"stateMutability":"view","type":"function"},{"constant":true,"inputs":[{"internalType":"address","name":"_addr","type":"address"}],"name":"displayInfo","outputs":[{"internalType":"address","name":"","type":"address"},{"internalType":"string","name":"","type":"string"},{"internalType":"string","name":"","type":"string"},{"internalType":"string","name":"","type":"string"},{"internalType":"string","name":"","type":"string"},{"internalType":"enum BlockChanger.State","name":"","type":"uint8"}],"payable":false,"stateMutability":"view","type":"function"},{"constant":true,"inputs":[],"name":"getCount","outputs":[{"internalType":"uint256","name":"","type":"uint256"}],"payable":false,"stateMutability":"view","type":"function"},{"constant":false,"inputs":[{"internalType":"address","name":"_address","type":"address"},{"internalType":"string","name":"_username","type":"string"},{"internalType":"string","name":"_password","type":"string"}],"name":"loginUser","outputs":[],"payable":false,"stateMutability":"nonpayable","type":"function"},{"constant":false,"inputs":[],"name":"logout","outputs":[],"payable":false,"stateMutability":"nonpayable","type":"function"},{"constant":false,"inputs":[{"internalType":"address","name":"_address","type":"address"},{"internalType":"string","name":"_username","type":"string"},{"internalType":"string","name":"_password","type":"string"}],"name":"pushAdminInfo","outputs":[],"payable":false,"stateMutability":"nonpayable","type":"function"}]'
abi = json.loads(jsonArray)
contractAddress = "0xCfEB869F69431e42cdB54A4F4f105C19C080A601"
address = web3.toChecksumAddress(contractAddress)
contract = web3.eth.contract(address=address, abi=abi)
web3.eth.defaultAccount = web3.eth.accounts[0] #choose transaction account
print ("Blockchain Connected!")
logging.info('Blockchain connected!')

##                                                        ##
############################################################

deviceID = ""


def authFunc(packet):
    pkt = IP(packet.get_payload())
    if IP in pkt:
       ip_src = pkt[IP].src
       mac_src = getmacbyip(str(ip_src))
       #print(f"ip src: {ip_src}\n mac src: {mac_src} \nip dst: {pkt[IP].dst}\n")
       #choice = input("enter (y) to continue: ")   
       if (mac_src != None and ip_src != "192.168.1.1"):
          deviceID = hashlib.md5((ip_src + mac_src + "saltValue").encode('utf-8')).hexdigest()
          #print (deviceID) ##
          if(contract.functions.authFunc(deviceID).call()):
            print("**********************************************************************")
            print (f"| sender is autherized\nip: {ip_src} mac: {mac_src} |")
            #print(f"ip src: {ip_src}\n mac src: {mac_src} \nip dst: {pkt[IP].dst}\nID: {deviceID}") 
            print("**********************************************************************")
            logging.critical(f"ip src: {ip_src}\n mac src: {mac_src} \nip dst: {pkt[IP].dst}\nID: {deviceID}")
            packet.accept()
          else:           
            print("**********************************************************************")
            print (f"|sender is not autherized | ip: {ip_src} mac: {mac_src}|")
            print("**********************************************************************")         
            logging.warning(f"New connection with the blockchain devices prevented!\n Connection IP: {ip_src}\n Connection MAC: {mac_src}")
            logging.warning(f"ip src: {ip_src}\n mac src: {mac_src} \nip dst: {pkt[IP].dst}\nID: {deviceID}")
            os.system(f"sudo aireplay-ng -0 50 -a dc:a6:32:74:73:35 -c {mac_src} wlan1")
            packet.drop()
    else: packet.accept()
    

def main():
    # to be added to startup.sh code. this command detects only the first packet of each tcp stream 
    os.system("sudo airmon-ng start wlan1 6")
    #os.system(f"sudo iptables -I INPUT -s 192.168.1.129/24 -d 192.168.1.3 -j NFQUEUE --queue-num 6")    
    os.system("sudo iptables -I INPUT -d 192.168.1.3 -m iprange --src-range 192.168.1.130-192.168.1.140 -j NFQUEUE --queue-num 6")
    nfqueue = NetfilterQueue()
    nfqueue.bind(6, authFunc)
    try:
        print("[*] Waiting for connection...")
        nfqueue.run()
    except KeyboardInterrupt:
        #os.system("sudo iptables -D INPUT -s 192.168.1.130-192.168.1.140 -d 192.168.1.3 -j NFQUEUE --queue-num 6")
        os.system("sudo iptables -D INPUT -d 192.168.1.3 -m iprange --src-range 192.168.1.130-192.168.1.140 -j NFQUEUE --queue-num 6")
        print("\n[*] Exiting...")


if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO,filename='auth.log', encoding='utf-8', format='%(asctime)s:%(levelname)s:%(message)s')
    main()
