default:
	@gcc stream_analyzer.c \
		 ../disk_analyzer/color.c \
		 ../datastructures/bst.c \
		 qemu_tracer.c \
		 tokenizer.c \
		 byte_printer.c \
		 deep_inspect.c \
		 -o stream_analyzer \
		 -Wall \
		 -Werror \
		 #-DNOCOLOR

infer: default
	@./stream_analyzer \
		/home/wolf/Dropbox/Projects/xray/sample/file_create_write_65k.log \
		| less -R

test: default
	@./stream_analyzer \
		/home/wolf/Dropbox/Projects/xray/sample/qemu_tinycore.raw.trace

clean:
	@rm stream_analyzer
