default:
	@clang disk_analyzer.c ../util/color.c ext2/ext2.c ext4/ext4.c ntfs/ntfs.c mbr/mbr.c \
		   ../bson/bson-encoder.c \
		   ../util/util.c \
		   ../datastructures/bitarray.c \
		   -o disk_analyzer \
		   -Wall \
		   -Werror \
		   -I../util \
		   -I../bson \
		   -I../datastructures \
		   -I./ext2/ \
		   -I./ext4/ \
		   -I./ntfs/ \
		   -I./mbr/ \
		   -g \
		   -lm
	@clang ext2/tools/inode_explorer.c ext2/ext2.c \
		   ../util/color.c mbr/mbr.c \
		   ../bson/bson-encoder.c \
		   ../util/util.c \
		   ../datastructures/bitarray.c \
		   -o ext2_inode_explorer \
		   -Wall \
		   -Werror \
		   -I../util \
		   -I../bson \
		   -I../datastructures \
		   -I./ext2/ \
		   -I./mbr/ \
		   -lm
	@clang ext2/tools/data_block_explorer.c ext2/ext2.c \
		   ../util/color.c mbr/mbr.c \
		   ../bson/bson-encoder.c \
		   ../util/util.c \
		   ../datastructures/bitarray.c \
		   -o ext2_data_block_explorer \
		   -Wall \
		   -Werror \
		   -I../util \
		   -I../bson \
		   -I../datastructures \
		   -I./ext2/ \
		   -I./mbr \
		   -lm
	@clang ext4/tools/data_block_explorer.c ext4/ext4.c \
		   ../util/color.c mbr/mbr.c \
		   ../bson/bson-encoder.c \
		   ../util/util.c \
		   ../datastructures/bitarray.c \
		   -o ext4_data_block_explorer \
		   -Wall \
		   -Werror \
		   -I../util \
		   -I../bson \
		   -I../datastructures \
		   -I./ext4/ \
		   -I./mbr/ \
		   -lm

test_ntfs: default
	@rm -rf /tmp/win7
	@mkdir /tmp/win7
	@time -- ./disk_analyzer \
		/home/wolf/VM/vm_ntfs_test/win7enterprise.raw.pristine \
		/tmp/win7enterprise.bson > /dev/null
	@ls -lah /tmp/win7enterprise.bson 
	@gzip --best -c /tmp/win7enterprise.bson > /tmp/win7enterprise.bson.gz
	@ls -lah /tmp/win7enterprise.bson.gz

test: default
	@time ./disk_analyzer \
		/home/wolf/VM/vm_ext4_test/vm_ext4_test.raw.pristine \
		/home/wolf/Dropbox/Projects/xray/sample/ext4_index.bson
	@ls -lah /home/wolf/Dropbox/Projects/xray/sample/ext4_index.bson
	@gzip --best -c \
		/home/wolf/Dropbox/Projects/xray/sample/ext4_index.bson \
	 	> /tmp/ext4_index.bson.gz
	@ls -lah /tmp/ext4_index.bson.gz

test_tinycore: default
	@valgrind --track-origins=yes ./disk_analyzer \
		/home/wolf/Dropbox/Projects/xray/sample/tinycore.raw \
		/tmp/tinycore.bson

	@../bson/bson_printer /tmp/tinycore.bson | less -R

clean:
	@rm disk_analyzer \
		ext2_data_block_explorer \
		ntfs_file_record_differ \
	    ext2_inode_explorer \
	    ext4_data_block_explorer \

inode_explorer: default
	./inode_explorer /home/wolf/Dropbox/Projects/xray/sample/tinycore.raw 

data_block_explorer: default
	./data_block_explorer /home/wolf/Dropbox/Projects/xray/sample/tinycore.raw

file_record_differ: default
	./file_record_differ /home/wolf/VM/win7enterprise.raw
