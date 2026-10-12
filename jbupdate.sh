#!/bin/bash

cd $(dirname $0);pwd
DEVICE=root@192.168.31.158
PORT=22

ssh $DEVICE "rm -rf /var/mobile/Documents/Dopamine.tipa"
scp ./Application/Dopamine.tipa $DEVICE:/var/mobile/Documents/Dopamine.tipa
ssh $DEVICE "/var/jb/basebin/jbctl update tipa /var/mobile/Documents/Dopamine.tipa"