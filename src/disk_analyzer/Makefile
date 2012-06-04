default:
	@clang disk_analyzer.c ../util/color.c ext2.c ntfs.c mbr.c \
		   ../bson/bson-encoder.c \
		   ../util/util.c \
		   -o disk_analyzer \
		   -Wall \
		   -Werror \
		   -I../util \
		   -I../bson \
		   -g
	@clang inode_explorer.c ext2.c \
		   ../util/color.c mbr.c \
		   ../bson/bson-encoder.c \
		   ../util/util.c \
		   -o inode_explorer \
		   -Wall \
		   -Werror \
		   -I../util \
		   -I../bson
	@clang data_block_explorer.c ext2.c \
		   ../util/color.c mbr.c \
		   ../bson/bson-encoder.c \
		   ../util/util.c \
		   -o data_block_explorer \
		   -Wall \
		   -Werror \
		   -I../util \
		   -I../bson
	@clang file_record_differ.c ntfs.c \
		   ../util/color.c mbr.c \
		   ../bson/bson-encoder.c \
		   ../util/util.c \
		   -o file_record_differ \
		   -Wall \
		   -Werror \
		   -I../util \
		   -I../bson

test: default
	@rm -rf /tmp/win7
	@mkdir /tmp/win7
	@./disk_analyzer \
		/home/wolf/VM/win7enterprise.raw \
		/tmp/win7enterprise.bson #| grep found > fnames

	#@valgrind --track-origins=yes ./disk_analyzer \
		#/home/wolf/VM/win7enterprise.raw \
		#/tmp/win7enterprise.bson

test_tinycore: default
	@valgrind --track-origins=yes ./disk_analyzer \
		/home/wolf/ropbox/Projects/xray/sample/tinycore.raw \
		/tmp/tinycore.bson

	@../bson/bson_printer /tmp/tinycore.bson | less -R

clean:
	@rm disk_analyzer *.gch

inode_explorer: default
	./inode_explorer /home/wolf/Dropbox/Projects/xray/sample/tinycore.raw 

data_block_explorer: default
	./data_block_explorer /home/wolf/Dropbox/Projects/xray/sample/tinycore.raw

file_record_differ: default
	./file_record_differ /home/wolf/VM/win7enterprise.raw
