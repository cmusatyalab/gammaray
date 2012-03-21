default:
	@gcc shell.c \
		 tail.c \
		 ../disk_analyzer/color.c \
		 ../disk_analyzer/ext2.c \
		 ../stream_analyzer/deep_inspect.c \
		 ../stream_analyzer/qemu_tracer.c \
		 ../datastructures/bst.c \
		 -o shell \
		 -Wall \
		 -Werror

test: default
	@./shell ../../sample/auth.log.edit.log

clean:
	@rm shell 
