default:
	@gcc bson_test.c bson.c ../disk_analyzer/color.c \
		 -o bson_test \
		 -Wall \
		 -Werror \
		 #-DNOCOLOR

test: default
	valgrind --leak-check=full --show-reachable=yes ./bson_test

clean:
	@rm bson_test
