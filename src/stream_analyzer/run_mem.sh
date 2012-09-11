#!/usr/bin/zsh

./inference_engine \
     /home/wolf/Dropbox/Projects/xray/sample/ext4_index.bson \
     /home/wolf/Dropbox/Projects/xray/sample/ext4_trace.bin \
     4 \
     /home/wolf/VM/vm_ext4_test/vm_ext4_test.raw \
     ext4_test_vm &

pid=$!

printf 'tracing pid %d' $pid > /tmp/status.log

while true 
do
    cat /proc/$pid/status >> /tmp/status.log
    sleep 0.01
done
