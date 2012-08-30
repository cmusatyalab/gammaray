default:
	@#clang inference_engine_ntfs_demo.c -g \
	#	 ../util/color.c \
	#	 ../util/util.c \
	#	 ../bson/bson-encoder.c \
	#	 ../bson/bson-decoder.c \
	#	 ../disk_analyzer/ext2/ext2.c \
	#	 ../disk_analyzer/ntfs/ntfs.c \
	#	 ../datastructures/bst.c \
	#	 ../datastructures/linkedlist.c \
	#	 deep_inspection.c \
	#	 redis_queue.c \
	#	 -lhiredis \
	#	 -o inference_engine_ntfs \
	#	 -Wall \
	#	 -Werror \
	#	 -I../disk_analyzer/ext2 \
	#	 -I../disk_analyzer/mbr \
	#	 -I../disk_analyzer/ntfs \
	#	 -I../util \
	#	 -I../bson \
	#	 -I../datastructures \
	#	 -I/usr/include/hiredis \
	#	 #-DNOCOLOR

	@clang inference_engine.c -g \
		 ../util/color.c \
		 ../util/util.c \
		 ../bson/bson-encoder.c \
		 ../bson/bson-decoder.c \
		 ../disk_analyzer/ext2/ext2.c \
		 ../datastructures/bst.c \
		 ../datastructures/linkedlist.c \
		 deep_inspection.c \
		 redis_queue.c \
		 -lhiredis \
		 -o inference_engine \
		 -Wall \
		 -Werror \
		 -I../disk_analyzer/ext2 \
		 -I../disk_analyzer/mbr \
		 -I../util \
		 -I../bson \
		 -I../datastructures \
		 -I/usr/include/hiredis \
		 #-DNOCOLOR

gdb: default
	@gdb --args ./inference_engine \
		/tmp/tinycore.bson \
		/home/wolf/Dropbox/Projects/xray/sample/file_create_write_65k.log

memtest: default
	@valgrind --leak-check=full --show-reachable=yes ./inference_engine \
		/tmp/tinycore.bson \
		/home/wolf/Dropbox/Projects/xray/sample/file_create_write_65k.log \
		| less -R

clean:
	@rm inference_engine
