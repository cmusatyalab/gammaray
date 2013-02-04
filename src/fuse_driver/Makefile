default:
	@gcc -Wall \
		 -Werror \
		 hello_fs.c \
		 -o hello_fs \
		 `pkg-config fuse --cflags --libs`

test: default
	@mkdir -p test
	@./hello_fs test
	@cat test/hello
	@sleep 0.25
	@sudo umount test
	@rm -rf test

clean:
	@rm -rf test
	@rm hello_fs
	@sudo umount test
