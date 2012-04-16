default:
	@clang stream_analyzer.c \
		 ../util/color.c \
		 ../datastructures/bst.c \
		 qemu_tracer.c \
		 deep_inspect.c \
		 -o stream_analyzer \
		 -Wall \
		 -Werror \
		 -I../util \
		 #-DNOCOLOR

	@clang analysis_engine.c \
		 ../util/color.c \
		 ../datastructures/bst.c \
		 ../datastructures/linkedlist.c \
		 qemu_tracer.c \
		 deep_inspect.c \
		 -o analysis_engine \
		 -Wall \
		 -Werror \
		 -I../util \
		 -I../datastructures \
		 #-DNOCOLOR

memtest: default
	@valgrind --leak-check=full --show-reachable=yes ./analysis_engine \
		/home/wolf/Dropbox/Projects/xray/sample/file_create_write_65k.log \
		| less -R

test: default
	@./analysis_engine \
		/home/wolf/Dropbox/Projects/xray/sample/file_create_write_65k.log \
		| less -R

test_stream: default
	@./stream_analyzer \
		/home/wolf/Dropbox/Projects/xray/sample/file_create_write_65k.log \
		| less -R

clean:
	@rm stream_analyzer
