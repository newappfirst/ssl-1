 #!/bin/bash
 #run me from the cert directory
 /usr/local/sbin/zmap -i wlan0 -p 443 -B 1M -n 50000 -o - | ../get_cert -p 443 -c 500 -a ../../ca/root-ca.crt
