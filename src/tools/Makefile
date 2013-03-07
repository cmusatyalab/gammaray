default: reverse_index

reverse_index:
	@clang \
		reverse_index.c \
		../bson/bson-decoder.c \
		../bson/bson-encoder.c \
		../bson/bson-util.c \
		../util/color.c \
		../util/util.c \
		-o reverse_index \
		-Wall \
		-Werror \
		-I../util \
		-I../bson \
		#-DNOCOLOR

test: clean reverse_index
	@./reverse_index \
		/home/wolf/Dropbox/Projects/xray/sample/ext4_index.bson \
		> /home/wolf/Dropbox/Projects/xray/sample/ext4_index_reverse.bin
	@hexdump \
		-e '"%.10d : %.10d\n"' \
		/home/wolf/Dropbox/Projects/xray/sample/ext4_index_reverse.bin | less 

clean:
	@rm -f reverse_index

test_tail:
	@python ./tail.py \
		localhost \
		'$(shell hostname):tinycore:/mnt/sda1/tce/blargh'
