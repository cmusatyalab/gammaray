default:
	@gcc shell.c \
		 tail.c \
		 ../disk_analyzer/color.c \
		 ../stream_analyzer/qemu_tracer.c \
		 -o shell \
		 -Wall \
		 -Werror

test: default
	@./shell -

clean:
	@rm shell 
