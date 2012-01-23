#!/bin/bash
if [ -z $1 ]
then
    echo "Usage: $0 decrypted_ramdisk.dmg"
    exit 1
fi

echo Copying..
cp "$1" /tmp/rd.dmg

echo Mounting..
hdiutil attach /tmp/rd.dmg >/dev/null

RAMDISK=/Volumes/ramdisk

if [ ! -d $RAMDISK ]
then
    echo "Mount failed!"
    exit 1
fi
if [ ! -f /tmp/pat ]
then 
    echo Creating the pattern..
	rm /tmp/pt 2>/dev/null
	for i in {1..16384}; do echo -ne "\x0d\xf0\xad\xba" >> /tmp/pt; done;
	mv /tmp/pt /tmp/pat
fi
echo Deleting baseband files to free up some space..
rm $RAMDISK/usr/standalone/firmware/*
echo Copying the pattern file..
cp /tmp/pat $RAMDISK/pattern
echo Unmounting..
hdiutil detach $RAMDISK >/dev/null
echo "Done: /tmp/rd.dmg; don't forget to run xpwntool to reencrypt" 