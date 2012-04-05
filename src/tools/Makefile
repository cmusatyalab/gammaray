default:
	@clang shell.c \
		 tail.c \
		 ../util/color.c \
		 ../disk_analyzer/ext2.c \
		 ../stream_analyzer/deep_inspect.c \
		 ../stream_analyzer/qemu_tracer.c \
		 ../datastructures/bst.c \
		 -o shell \
		 -Wall \
		 -Werror \
		 -I../util

test: default
	@./shell ../../sample/auth.log.edit.log

clean:
	@rm shell 
