#!/bin/zsh

echo '--- Computed sha256sums from Reconstructed Files ---\n'

for l in `find /home/wolf/copydisk -type f | sort`     
do
    sha256sum $l
done     

echo '\n--- Reference sha256sums from Original Disk Image---\n'

for l in `sudo find /home/wolf/originaldisk -type f | sort`     
do
    sudo sha256sum $l
done     
