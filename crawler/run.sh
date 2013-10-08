 #!/bin/bash
 #run me from the cert directory
 /usr/local/sbin/zmap -i wlan0 -p 443 -B 4M -n 2500000 -o - | ../get_cert -p 443 -c 100000 -f ../../ca/root-ca.crt
