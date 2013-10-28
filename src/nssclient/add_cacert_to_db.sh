#!/bin/bash
mkdir $1
certutil -N -d $1
certutil -A -n testca -d $1 -i $2 -t C,C,C
