default:
	@clang \
         bson_test.c bson-encoder.c bson-decoder.c \
		 ../util/util.c \
		 ../disk_analyzer/color.c \
		 -o bson_test \
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

clean:
	@rm bson_test
