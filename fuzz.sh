#!/bin/bash

sudo sysctl -w kern.sysv.shmmax=16777216
sudo sysctl -w kern.sysv.shmall=65536
sudo sysctl -w kern.sysv.shmmin=1
sudo sysctl -w kern.sysv.shmmni=32
sudo sysctl -w kern.sysv.shmseg=8
sudo sysctl -w kern.sysv.shm_use_pshared=0

SL=/System/Library; PL=com.apple.ReportCrash
launchctl unload -w ${SL}/LaunchAgents/${PL}.plist
sudo launchctl unload -w ${SL}/LaunchDaemons/${PL}.Root.plist

mkdir -p inputs && echo 'seed' > inputs/test.txt
afl-fuzz -i inputs -o outputs -- ./kyu_fuzz @@
