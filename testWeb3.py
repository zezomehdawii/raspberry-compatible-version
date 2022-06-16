from web3 import Web3
import json
import hashlib
from eth_API import *
from web3.auto import w3
import asyncio
##################################################
##                Blockchain Info               ##
blockchainNetworkIP = "http://localhost:7545"
web3 = Web3(Web3.HTTPProvider(blockchainNetworkIP))
jsonArray = '[{"constant":false,"inputs":[{"internalType":"string","name":"_hash_id","type":"string"}],"name":"Activate","outputs":[{"internalType":"bool","name":"","type":"bool"}],"payable":false,"stateMutability":"nonpayable","type":"function"},{"constant":false,"inputs":[{"internalType":"address","name":"_addr","type":"address"},{"internalType":"string","name":"_name","type":"string"},{"internalType":"string","name":"_hash_id","type":"string"}],"name":"add_device","outputs":[],"payable":false,"stateMutability":"nonpayable","type":"function"},{"constant":true,"inputs":[{"internalType":"string","name":"_hash_id","type":"string"}],"name":"authFunc","outputs":[{"internalType":"bool","name":"","type":"bool"}],"payable":false,"stateMutability":"view","type":"function"},{"constant":false,"inputs":[{"internalType":"string","name":"_hash_id","type":"string"}],"name":"deActivate","outputs":[{"internalType":"bool","name":"","type":"bool"}],"payable":false,"stateMutability":"nonpayable","type":"function"},{"constant":true,"inputs":[{"internalType":"address","name":"","type":"address"}],"name":"device","outputs":[{"internalType":"string","name":"name","type":"string"},{"internalType":"string","name":"hash_id","type":"string"},{"internalType":"enum BlockChanger.State","name":"device_state","type":"uint8"}],"payable":false,"stateMutability":"view","type":"function"},{"constant":true,"inputs":[],"name":"deviceCount","outputs":[{"internalType":"uint256","name":"","type":"uint256"}],"payable":false,"stateMutability":"view","type":"function"},{"constant":true,"inputs":[{"internalType":"address","name":"_addr","type":"address"}],"name":"displayInfo","outputs":[{"internalType":"string","name":"","type":"string"},{"internalType":"string","name":"","type":"string"},{"internalType":"enum BlockChanger.State","name":"","type":"uint8"},{"internalType":"uint256","name":"","type":"uint256"}],"payable":false,"stateMutability":"view","type":"function"},{"constant":true,"inputs":[],"name":"getCount","outputs":[{"internalType":"uint256","name":"","type":"uint256"}],"payable":false,"stateMutability":"view","type":"function"},{"constant":true,"inputs":[{"internalType":"uint256","name":"","type":"uint256"}],"name":"signed_addresses","outputs":[{"internalType":"address","name":"","type":"address"}],"payable":false,"stateMutability":"view","type":"function"}]'
abi = json.loads(jsonArray)
address = web3.toChecksumAddress("0xf7f770FA8eb0dee4492e8fB45af454A5718572DC")
web3.eth.defaultAccount = web3.eth.accounts[0]
#personal_nulockAccount(web3.eth.defaultAccount)
#here need to add unlock function the default account before making any transactions!
#address = web3.toChecksumAddress(address)
contract = web3.eth.contract(address=address, abi=abi)
##################################################

def add():
    ip_src = "192.168.100.2"
    mac_src = "ff:rr:aa:dd"
    #addr = web3.toChecksumAddress("0x8AAFdb6973C27B4F08C41515B56A5d6f72927815")
    #addr = web3.toChecksumAddress(personal_newAccount_and_unlock())
    addr = web3.eth.accounts[0]
    print ("this address: "+ addr)
    deviceName = input("Enter device Name: ") # get device name
    deviceID = hashlib.md5((ip_src + mac_src + "saltValue").encode('utf-8')).hexdigest()# calculate the id
    tx_hash = contract.functions.add_device(addr, deviceName, deviceID).transact() # store the id to the blockchain
    #print(web3.eth.waitForTransactionReceipt(tx_hash)) # stops the code execution until transaction is done.
    web3.eth.wait_for_transaction_receipt(tx_hash)
    print("Transaction receipt mined:")
    print ("\n----------------\n<++ [ADDED!] ++>\n----------------")
    #a = web3.eth.account.create("password")
    print (tx_hash)
    print("-----------------------------------------")
    print(web3.eth.blockNumber)
    o = input("enter")
    #print(contract.functions.displayInfo(addr).call())
    deviceCount = contract.functions.getCount().call()
    print(deviceCount)
    #tx_has2 = contract.functions.getCount().call()
    #print (contract.functions.getCount().call())
    #print (tx_has2)

async def log_loop(event_filter, poll_interval):
    while True:
        print("log")
        print(event_filter.get_new_entries())
        for event in event_filter.get_new_entries():
            print("event")
            add(event)
        await asyncio.sleep(poll_interval)

def oldmain():
    print("main")
    block_filter = w3.eth.filter('latest')
    tx_filter = w3.eth.filter('pending')
    loop = asyncio.get_event_loop()
    try:
        print("try")
        loop.run_until_complete(
            asyncio.gather(
                log_loop(block_filter, 2),
                log_loop(tx_filter, 2)))
    finally:
        loop.close()

def main():
    add()
if __name__ == '__main__':
    main()