#!/bin/bash

a1="0x"`cat /proc/kallsyms | grep ' page_is_ram' | head -1 |cut -d ' ' -f 1`


if [ "$a1" == "0x" ]; then
	echo "Cannot find symbol 'page_is_ram'";
	exit;
fi

echo -n "Module: insmod fmem.ko a1=$a1 : ";
insmod fmem.ko a1="$a1" || exit;
echo "OK";
echo -n "Device: "; sleep 1;ls /dev/fmem
echo "----Memory areas: -----"
cat /proc/mtrr;
echo "-----------------------"
echo "!!! Don't forget add \"count=\" to dd !!!";
