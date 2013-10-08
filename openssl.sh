#!/bin/bash
tempfile="/tmp/$(basename $0).$RANDOM"
openssl s_client -connect $1:$2 -CAfile $3 > $tempfile
verify=`grep "Verify return code" < $tempfile`
if [ $? -eq 0 ]; then
	echo $verify
fi
rm $tempfile
