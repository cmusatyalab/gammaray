default:
	@clang bst_test.c bst.c ../util/color.c \
		 -o bst_test \
		 -Wall \
		 -Werror \
		 -I../util \
		 #-DNOCOLOR
	@clang linkedlist_test.c linkedlist.c ../util/color.c -g\
		 -o linkedlist_test \
		 -Wall \
		 -Werror \
		 -I../util \
		 #-DNOCOLOR
	@clang bitarray_test.c bitarray.c ../util/color.c ../util/util.c -g \
		-o ba_test \
		-Wall \
		-Werror \
		-I../util \
		-lm

test: default
	./ba_test

test_valgrind: default
	valgrind --leak-check=full --show-reachable=yes -v ./ba_test

clean:
	@rm bst_test 
	@rm linkedlist_test
	@rm ba_test
