#!/bin/zsh

list=(`make test | grep Reconstructed | cut -d ':' -f 2 | tr -d ' '`)

for l in $list
do
    sha256sum $l
done
