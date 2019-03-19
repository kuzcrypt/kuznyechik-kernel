.PHONY: test clean

test: test-ciphers
	./test-ciphers

test-ciphers: test-ciphers.c
	$(CC) test-ciphers.c -o $@

clean:
	rm -f test-ciphers
