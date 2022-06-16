import os

with open("ip_list.txt","r") as fr:
    iplist = fr.read()
    with open("ip_list.txt","w") as fw:
        print ("<++ [ADDING NEW DEVICE TO THE BLOCKCHAIN] ++> ")
        while True:
            new_ip = input("Enter device ip address: ")
            if new_ip not in iplist: 
                if len(iplist) == 0 : iplist = iplist + new_ip 
                else: iplist = iplist + "," + new_ip
                print ("<++ [ADDED!] ++>")
                choice = input("Do you want to add more? y/n: ")
                if choice == "n": 
                    fw.write(iplist) 
                    break
            else: 
                print (f"The entered IP [{new_ip}] is already exists!")
                choice = input("Do you want to add more? y/n: ")
                if choice == "n":
                    fw.write(iplist)
                    break   
        
      
print("++++++++++++++++++++++++++++++++++++++++++++++++++")
print("                  Devices List                    ")
print(f"{iplist}                     ")
print("++++++++++++++++++++++++++++++++++++++++++++++++++")

reboot = input(" <++[NOTE!] ++>\nYou must reboot the BlockChanger in order to allow new settings to take action \nDo you want to reboot now? y/n: ")
if reboot == "y": os.system("sudo reboot")
