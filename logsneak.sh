#!/bin/bash

# v0: Invalid user & Did not receive info
# v1: Bad protocol verson
# v2: Connection closed, "from|by"

LOG=/var/log/secure

tail -F --pid=$$ -n 0 $LOG | while read
do
	isbad=$(echo $REPLY | grep "Invalid user\|Did not receive identification string\|Bad protocol version\|Connection closed by ")
	if [ ${#isbad} -ne 0 ]
	then
		#badip=${isbad#* from }
		#badip=${badip% port *}
		badip=$(echo "$isbad" | sed -e "s/.* \(from\|by\) //")

		#echo "Blocking $badip"
		#echo "original: $isbad"
		logger -i -p authpriv.info "Starting ban of IP ${badip}"

		echo +"${badip}" >> /proc/net/xt_recent/sshbadlogin
	fi
done
