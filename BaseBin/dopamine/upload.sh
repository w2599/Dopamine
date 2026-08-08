#/bin/sh
set -e

make

ssh loki "mkdir -p /mnt6/preboot/dopamine-tmp"
ssh loki "rm -rf /mnt6/preboot/dopamine-tmp/dopamine"
scp -O dopamine loki:/mnt6/preboot/dopamine-tmp/dopamine

ssh loki "injecttotrustcache /mnt6/preboot/dopamine-tmp/dopamine"
