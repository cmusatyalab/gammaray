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

	@clang stream_analyzer.c \
		 ../util/color.c \
		 ../util/util.c \
		 ../datastructures/bst.c \
		 qemu_tracer.c \
		 deep_inspect.c \
		 -o stream_analyzer \
		 -Wall \
		 -Werror \
		 -I../util \
		 #-DNOCOLOR

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

test: default
	@./inference_engine_ntfs \
		/home/wolf/VM/demo.txt.txt.fr.bin \
		/home/wolf/VM/win7enterprise.bootf.bin \
		0x0000000006500000 \
		/home/wolf/VM/win7enterprise.log \
		win7enterprise \
		2>/dev/null \
		| less -R

test_live: default
	@./inference_engine_ntfs \
		/home/wolf/VM/demo.txt.txt.fr.bin \
		/home/wolf/VM/win7enterprise.bootf.bin \
		0x0000000006500000 \
		/tmp/win7enterprise.log \
		win7enterprise \
		2>/dev/null \
		| less -R

test_stream: default
	@./stream_analyzer \
		/home/wolf/Dropbox/Projects/xray/sample/file_create_write_65k.log \
		| less -R

clean:
	@rm stream_analyzer
	@rm inference_engine
