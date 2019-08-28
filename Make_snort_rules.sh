#!/bin/bash
#assigns the sid var for the alert sid counter
sid=1000000

echo "alert tcp 80.255.10.236 any <> any any (msg:"APT28 80.255.10.236"; sid:2104008;)" > /etc/nsm/rules/local.rules
echo "alert udp any any -> any any (msg:\"APT28 wscapi\"; content:\"wscapi\"; sid:2105070;)" >> /etc/nsm/rules/local.rules

#reads file iocips.txt and adds the ip from the text document to the snort rule database
for ipaddr in $(cat /home/student/iocipsclean.txt)
	do
	echo "alert ip $ipaddr any <> any any (msg:\"APT28 $ipaddr\"; sid:$sid;)" >> /etc/nsm/rules/local.rules
	((sid++))
done

#reads file iocdomains.txt and adds the domain from the text document to the snort rule database
for ipdom in $(cat /home/student/iocdomainscleancut.txt)
	do
	echo "alert udp any any <> any any (msg:\"APT28 $ipdom\"; content:\"$ipdom\"; nocase; sid:$sid;)" >> /etc/nsm/rules/local.rules
	((sid++))
done

