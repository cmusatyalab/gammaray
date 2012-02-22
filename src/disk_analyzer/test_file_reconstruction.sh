#!/bin/zsh

list=(`make test | grep Reconstructed | cut -d ':' -f 2 | tr -d ' '`)

echo '--- Computed sha256sums from Reconstructed Files ---\n'

for l in $list
do
    sha256sum $l
done

echo '\n--- Reference sha256sums from Original Disk Image---\n'

cat ../../sample/gold_sha256.list
