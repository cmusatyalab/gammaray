default:
	@clang disk_analyzer.c ../util/color.c ext2.c mbr.c \
		   ../bson/bson-encoder.c \
		   -o disk_analyzer \
		   -Wall \
		   -Werror \
		   -I../util \
		   -I../bson \
		   #-DNOCOLOR
	@clang inode_explorer.c ext2.c \
		   ../util/color.c mbr.c \
		   ../bson/bson-encoder.c \
		   -o inode_explorer \
		   -Wall \
		   -Werror \
		   -I../util \
		   -I../bson
	@clang data_block_explorer.c ext2.c \
		   ../util/color.c mbr.c \
		   ../bson/bson-encoder.c \
		   -o data_block_explorer \
		   -Wall \
		   -Werror \
		   -I../util \
		   -I../bson

test: default
	@valgrind --track-origins=yes ./disk_analyzer \
		/home/wolf/Dropbox/Projects/xray/sample/tinycore.raw \
		/tmp/tinycore.bson

	#@../bson/bson_printer /tmp/tinycore.bson | less -R

bigtest: default
	@./disk_analyzer /home/wolf/sample_virtual_disks/tinycore_big.img

demo: default
	./disk_analyzer /home/wolf/Dropbox/Projects/xray/sample/tinycore.raw | \
	less -ru

clean:
	@rm disk_analyzer *.gch

inode_explorer: default
	./inode_explorer /home/wolf/Dropbox/Projects/xray/sample/tinycore.raw 

data_block_explorer: default
	./data_block_explorer /home/wolf/Dropbox/Projects/xray/sample/tinycore.raw
