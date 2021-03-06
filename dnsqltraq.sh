#!/bin/bash

# track dnsmasq log and turn it into something less bad

#defaultsFile=/etc/sysconfig/dnsqltraq
defaultsFile=/home/jmacleod/scratch/dnsqltraq

# Need $dbuser and $dbpswd
[[ -f $defaultsFile ]] && . $defaultsFile || exit 1

infile=${infile:-/var/log/dnsmasq.log}
userfile=${userfile:-"/etc/openvpn/ipp.txt /etc/openvpn/ipp-tcp.txt"}

declare -A client
declare -A userMap

function rebuildUsers() {
	# pull openvpn's user file and turn it into an assoc array
	userfileTmp=$(mktemp)
	for uf in $userfile; do
		awk 'BEGIN { FS = "," }; {printf "userMap[%s]=\"%s\"\n",$2, $1}' $uf >> $userfileTmp
	done
	. $userfileTmp
	rm $userfileTmp
}

uftime=0
for uf in $userfile; do
	tuftime=$(stat -c %Y $uf)
	if [ $tuftime -gt $uftime ]; then
		uftime=$tuftime
	fi
done

rebuildUsers

export HANDLE

tail -F --pid=$$ -n 0 $infile | while read
do

	# 3rd field after syslog header:
	# "from" is a query, "is" is a resolution

	msgtype=${REPLY% *}
	msgtype=${msgtype##* }

	case "$msgtype" in
		from) # queries
			# for now just handle A and AAAA
			# "query[A] www.google.com from 127.0.1.1"
			# "query[AAAA] settings.crashlytics.com from 203.0.118.6"
			# "query[PTR] 147.232.85.209.in-addr.arpa from 127.0.1.1"

			# Pop the syslog header, then extract the fields
			isq=${REPLY#*\]: }

			dom=${isq#* }
			dom=${dom%% *}

			cli=${isq##* }

			# Use usernames not client IPs
			for uf in $userfile; do
				uftimeNow=$(stat -c %Y $uf)
				if [ $uftimeNow -gt $uftime ]
				then
					uftime=$uftimeNow
					rebuildUsers
				fi
			done

			# use associative array as reply lookup
			client[$dom]=${userMap[$cli]}
		;;
		is) # reply
			# "reply www.google.com is 209.85.232.106"
			# "reply 209.85.232.147 is qt-in-f147.1e100.net"
			# "reply settings.crashlytics.com is <CNAME>"
			# "reply settings-crashlytics-1410998606.us-east-1.elb.amazonaws.com is NODATA-IPv6"
			# "cached settings.crashlytics.com is <CNAME>"
			# "/etc/pihole/gravity.list ads.nexage.com is 2602:ffc5::3f95:a969"
			# "/etc/pihole/gravity.list ads.nexage.com is 203.0.118.254"
			# "/etc/glasscleaner/ti-list.txt 001wen.com is 203.0.118.253"

			# Pop the syslog header, then extract the fields
			isr=${REPLY#*\]: }

			# domain: pop 1st field, then fields 3+
			dom=${isr#* }
			dom=${dom%% *}

			if [ -n "${client[$dom]}" ]
			then
				src=${isr%% *}

				# set default output fields
				srcout=$src
				domout=$dom

				# discard domain info
				# info level is creepy
				# TODO: change this to option
#				if [ "$src" == "reply" ]||[ "$src" == "cached" ]; then
#					domout=""
#				fi

				# change logging for NXDOMAIN to include domain
				# resaddr is last field = {NXDOMAIN-IPv4|NXDOMAIN-IPv6}
				resaddr=${isr##* }
				resaddr=${resaddr%-*}
				if [ "$resaddr" == "NXDOMAIN" ]; then
					srcout=$resaddr
				fi

				tstamp=$(date -d "${REPLY%% dnsmasq\[*}" --rfc-3339=seconds)
				#echo "$tstamp|${client[$dom]}|$domout|$srcout" >> $outfile
				qdr="INSERT INTO dnsqltraq "
				qdr+="(time, cert, domain, method) "
				qdr+="VALUES ('$tstamp', '${client[$dom]}', '$domout', '$srcout')"

				#echo "$qdr"
				mysql -u ${dbuser} -p${dbpswd} -D dnslog -e "$qdr"
				if [ $? -ne 0 ]; then
					exit 1
				fi

				# deal with overlap between adlist and tilist
				# ti is more important, don't let ads mask
				#FIXME this creates a memory leak :-(
				# idea: async cleanup a few seconds later?
				if [ "$srcout" == "/etc/pihole/gravity.list" ]; then
					:
				else
					unset client[$dom]
				fi
			fi
		;;
	esac
done
