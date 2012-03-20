default:
	@gcc bst_test.c bst.c ../disk_analyzer/color.c \
		 -o bst_test \
		 -Wall \
		 -Werror \
		 #-DNOCOLOR

test: default
	valgrind ./bst_test

clean:
	@rm bst_test 
