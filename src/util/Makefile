default:
	@gcc \
         bson_test.c bson.c util.c ../disk_analyzer/color.c \
		 -o bson_test \
		 -Wall \
		 -Werror \
		 #-DNOCOLOR

test: default
	@valgrind \
		--leak-check=full \
		--show-reachable=yes \
		--track-origins=yes \
		./bson_test

clean:
	@rm bson_test
