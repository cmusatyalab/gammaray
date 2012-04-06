default:
	@clang \
         bson_test.c bson-encoder.c bson-decoder.c \
		 ../util/util.c \
		 ../util/color.c \
		 -o bson_test \
		 -Wall \
		 -Werror \
		 -I../util \
		 #-DNOCOLOR
	
	@clang \
		bson_printer.c bson-decoder.c bson-encoder.c bson-util.c \
		../util/color.c \
		../util/util.c \
		-o bson_printer \
		-Wall \
		-Werror \
		-I../util \
		#-DNOCOLOR

test: default
	@valgrind \
		--leak-check=full \
		--show-reachable=yes \
		--track-origins=yes \
		./bson_test

bson_printer: default
	@valgrind \
		--leak-check=full \
		--show-reachable=yes \
		--track-origins=yes \
		./bson_printer /tmp/tinycore.0.pte

clean:
	@rm bson_test
