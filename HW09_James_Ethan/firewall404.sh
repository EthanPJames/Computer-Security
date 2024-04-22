#!/bin/sh
#Might have to add sudo in front of everything or may need to run with a sudo to avoid putting sudo in front of everything

#***********************************************#ADPATED FROM AVI KAK LECTURE SLIDES********************************************

#****************************************************************************************************************************************
# 1. Flush and delete all previously defined rules and chains
#Flush previous rules 
iptables -t filter -F
iptables -t filter -X
iptables -t mangle -F
iptables -t mangle -X
iptables -t nat    -F
iptables -t nat    -X
iptables -t raw    -F
iptables -t raw    -X
#****************************************************************************************************************************************
# 2. Write a rule that only accepts packets that originate from f1.com.
iptables -A INPUT -s f1.com -j ACCEPT

#****************************************************************************************************************************************
# 3. For all outgoing packets, change their source IP address to your own
# machine’s IP address (Hint: Refer to the MASQUERADE target in the
# nat table).
iptables -t nat -A POSTROUTING -o eth0 -j MASQUERADE #May be eth1
#****************************************************************************************************************************************
# 4. Write a rule to protect yourself against indiscriminate and nonstop
# scanning of ports on your machine.
iptables -A FORWARD -p tcp --tcp-flags SYN,ACK,FIN,RST SYN -m limit --limit 1/s -j ACCEPT #Check to make sure correct
#****************************************************************************************************************************************
# 5. Write a rule to protect yourself from a SYN-flood Attack by limiting
# the number of incoming ’new connection’ requests to 1 per second once
# your machine has reached 500 requests.

#NOT SURE ABOUT THIS ONE
iptables -A FORWARD -p tcp --tcp-flags SYN,ACK,FIN,RST SYN -m limit --limit 1/s --limit-burst 500 -j ACCEPT

#****************************************************************************************************************************************
# 6. Write a rule to allow full loopback access on your machine i.e. access
# using localhost
# (Hint: You will need two rules, one for the INPUT chain and one the
# OUTPUT chain on the FILTER table. The interface is ’lo’.)

#Loopback for input chain
iptables -A INPUT -i lo -j ACCEPT

#Loopback for output chain
iptables -A OUTPUT -o lo -j ACCEPT

#****************************************************************************************************************************************
# 7. Write a port forwarding rule that routes all traffic arriving on port
# 8888 to port 25565. Make sure you specify the correct table and chain.
# Subsequently, the target for the rule should be DNAT.
iptables -t nat -A PREROUTING -p tcp --dport 8888 -j DNAT --to-destination 127.0.0.1:25565
#****************************************************************************************************************************************
# 8. Write a rule that only allows outgoing ssh connections to
# engineering.purdue.edu. You will need two rules, one for the INPUT
# chain and one for the OUTPUT chain and one the FILTER table. Make
# sure to specify the correct options for the --state suboption for both rules

#Input chains
iptables -A INPUT -p tcp --dport 22 -s 128.46.104.20 -m state --state ESTABLISHED -j ACCEPT

#Ouptut chains
iptables -A OUTPUT -p tcp --dport 22 -d 128.46.104.20 -m state --state NEW,ESTABLISHED -j ACCEPT 


#****************************************************************************************************************************************
# 9. Drop any other packets if they are not caught by the above rules.

#Rule for dropping incoming packets that don't satisfy above rules
iptables -A INPUT -j DROP

#Rule for dropping outgoing packets that don't satisfy above rules
iptables -A OUTPUT -j DROP

#RUle for dropping packets that don't satisfy above rules
iptables -A FORWARD -j DROP
