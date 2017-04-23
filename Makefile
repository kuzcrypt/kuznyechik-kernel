SHELL=/bin/bash

version = 1.0

obj-m += kuznyechik.o
obj-m += magma.o


all:
	@echo "To install, run \`sudo make install\`"

modules:
	make -C "/lib/modules/$(shell uname -r)/build" M=$(shell pwd) modules

clean:
	make -C "/lib/modules/$(shell uname -r)/build" M=$(shell pwd) clean

install:
	rm -rf "/usr/src/kuznyechik-kernel-"*
	mkdir "/usr/src/kuznyechik-kernel-1.0"
	cp -f *".c" "dkms.conf" "Makefile" "/usr/src/kuznyechik-kernel-1.0"
	-dkms add -m "kuznyechik-kernel" -v $(version)
	dkms build -m "kuznyechik-kernel" -v $(version)
	dkms install -m "kuznyechik-kernel" -v $(version)

uninstall:
	modprobe -r kuznyechik magma
	dkms remove "kuznyechik-kernel/$(version)" --all
	rm -rf "/usr/src/kuznyechik-kernel-$(version)"
