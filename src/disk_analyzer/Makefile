default:
	@clang disk_analyzer.c ../util/color.c ext2/ext2.c ext4/ext4.c ntfs/ntfs.c mbr/mbr.c \
		   ../bson/bson-encoder.c \
		   ../util/util.c \
		   -o disk_analyzer \
		   -Wall \
		   -Werror \
		   -I../util \
		   -I../bson \
		   -I./ext2/ \
		   -I./ext4/ \
		   -I./ntfs/ \
		   -I./mbr/ \
		   -g
	@clang ext2/tools/inode_explorer.c ext2/ext2.c \
		   ../util/color.c mbr/mbr.c \
		   ../bson/bson-encoder.c \
		   ../util/util.c \
		   -o ext2_inode_explorer \
		   -Wall \
		   -Werror \
		   -I../util \
		   -I../bson \
		   -I./ext2/ \
		   -I./mbr/
	@clang ext2/tools/data_block_explorer.c ext2/ext2.c \
		   ../util/color.c mbr/mbr.c \
		   ../bson/bson-encoder.c \
		   ../util/util.c \
		   -o ext2_data_block_explorer \
		   -Wall \
		   -Werror \
		   -I../util \
		   -I../bson \
		   -I./ext2/ \
		   -I./mbr	
	@clang ext4/tools/inode_explorer.c ext4/ext4.c \
		   ../util/color.c mbr/mbr.c \
		   ../bson/bson-encoder.c \
		   ../util/util.c \
		   -o ext4_inode_explorer \
		   -Wall \
		   -Werror \
		   -I../util \
		   -I../bson \
		   -I./ext4/ \
		   -I./mbr/
	@clang ext4/tools/data_block_explorer.c ext4/ext4.c \
		   ../util/color.c mbr/mbr.c \
		   ../bson/bson-encoder.c \
		   ../util/util.c \
		   -o ext4_data_block_explorer \
		   -Wall \
		   -Werror \
		   -I../util \
		   -I../bson \
		   -I./ext4/ \
		   -I./mbr//
	@clang ntfs/tools/file_record_differ.c ntfs/ntfs.c \
		   ../util/color.c mbr/mbr.c \
		   ../bson/bson-encoder.c \
		   ../util/util.c \
		   -o ntfs_file_record_differ \
		   -Wall \
		   -Werror \
		   -I../util \
		   -I../bson \
		   -I./ntfs/ \
		   -I./mbr/

test: default
	@rm -rf /tmp/win7
	@mkdir /tmp/win7
	@./disk_analyzer \
		/home/wolf/VM/vm_ntfs_test/win7enterprise.raw \
		/tmp/win7enterprise.bson #| grep found > fnames

test_ext4: default
	@time ./disk_analyzer \
		/home/wolf/VM/vm_ext4_test/vm_ext4_test.raw.pristine \
		/home/wolf/Dropbox/Projects/xray/sample/ext4_index.bson
	#@../bson/bson_printer \
	#	/home/wolf/Dropbox/Projects/xray/sample/ext4_index.bson | \
 	#	head -n 200
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
	    ext4_inode_explorer	

inode_explorer: default
	./inode_explorer /home/wolf/Dropbox/Projects/xray/sample/tinycore.raw 

data_block_explorer: default
	./data_block_explorer /home/wolf/Dropbox/Projects/xray/sample/tinycore.raw

file_record_differ: default
	./file_record_differ /home/wolf/VM/win7enterprise.raw
