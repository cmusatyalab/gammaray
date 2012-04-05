default:
	@clang bst_test.c bst.c ../util/color.c \
		 -o bst_test \
		 -Wall \
		 -Werror \
		 -I../util \
		 #-DNOCOLOR

test: default
	valgrind ./bst_test

clean:
	@rm bst_test 
