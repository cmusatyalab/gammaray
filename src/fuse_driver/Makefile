default:
	@gcc -Wall \
		 -Werror \
		 xray_fs.c \
		 -o xray_fs \
		 `pkg-config fuse --cflags --libs`

test:
	@mkdir -p test
	@./xray_fs test
	@ls test
	@sleep 0.25
	@sudo umount test
	@rm -rf test

clean:
	@rm -rf test
	@rm xray_fs
	@sudo umount test

hellofs:
	@gcc -Wall \
		 -Werror \
		 hello_fs.c \
		 -o hello_fs \
		 `pkg-config fuse --cflags --libs`

test_hellofs: default
	@mkdir -p test
	@./hello_fs test
	@cat test/hello
	@sleep 0.25
	@sudo umount test
	@rm -rf test

clean_hellofs:
	@rm -rf test
	@rm hello_fs
	@sudo umount test
