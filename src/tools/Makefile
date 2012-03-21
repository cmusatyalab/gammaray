default:
	@gcc shell.c \
		 tail.c \
		 ../disk_analyzer/color.c \
		 ../stream_analyzer/deep_inspect.c \
		 ../stream_analyzer/qemu_tracer.c \
		 ../datastructures/bst.c \
		 -o shell \
		 -Wall \
		 -Werror

test: default
	@./shell ../../sample/file_create_write_65k.log

clean:
	@rm shell 
