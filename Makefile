version = 1.0

obj-m += kuznyechik.o
obj-m += magma.o

.PHONY: all modules clean install uninstall test test-clean

all: install

modules:
	make -C /lib/modules/${KVERSION}/build M=$(shell pwd) modules

clean: test-clean
	make -C "/lib/modules/${KVERSION}/build" M=$(shell pwd) clean

tests/test-ciphers: tests/test-ciphers.c
	$(CC) tests/test-ciphers.c -o $@

test: tests/test-ciphers
	tests/test-ciphers

test-clean:
	rm -f tests/test-ciphers

install:
	rm -rf "/usr/src/kuznyechik-kernel-"*
	mkdir "/usr/src/kuznyechik-kernel-1.0"
	cp -f *".c" "dkms.conf" "Makefile" "/usr/src/kuznyechik-kernel-1.0"
	-dkms add -m "kuznyechik-kernel" -v $(version)
	dkms build -m "kuznyechik-kernel" -v $(version)
	dkms install -m "kuznyechik-kernel" -v $(version)

uninstall:
	@modprobe -r kuznyechik magma
	dkms remove "kuznyechik-kernel/$(version)" --all
	rm -rf "/usr/src/kuznyechik-kernel-$(version)"
