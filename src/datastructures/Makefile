default:
	@clang bst_test.c bst.c ../util/color.c \
		 -o bst_test \
		 -Wall \
		 -Werror \
		 -I../util \
		 #-DNOCOLOR
	@clang linkedlist_test.c linkedlist.c ../util/color.c \
		 -o linkedlist_test \
		 -Wall \
		 -Werror \
		 -I../util \
		 #-DNOCOLOR

test: default
	valgrind --leak-check=yes ./linkedlist_test

clean:
	@rm bst_test 
	@rm linkedlist_test
