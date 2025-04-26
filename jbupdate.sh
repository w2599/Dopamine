#!/bin/bash

cd $(dirname $0);pwd
DEVICE=root@192.168.31.158
PORT=2222

ssh -p $PORT $DEVICE "rm -rf /var/mobile/Documents/Dopamine.tipa"
scp -P $PORT ./Application/Dopamine.tipa $DEVICE:/rootfs/var/mobile/Documents/Dopamine.tipa
ssh -p $PORT $DEVICE "/basebin/jbctl update tipa /var/mobile/Documents/Dopamine.tipa"

rm -f ./Application/Dopamine.tipa