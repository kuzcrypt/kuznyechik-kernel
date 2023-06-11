package = kuznyechik-kernel
version = 1.0

obj-m += kuznyechik.o
obj-m += magma.o

.PHONY: all install uninstall modules modules_install clean

all:
	@echo "To install, run \`sudo make install\`"

install:
	rm -rf /usr/src/$(package)-*
	mkdir /usr/src/$(package)-$(version)
	cp -f *.c dkms.conf Makefile /usr/src/$(package)-$(version)
	dkms add -m $(package) -v $(version)
	dkms build -m $(package) -v $(version)
	dkms install -m $(package) -v $(version)

uninstall:
	modprobe -r kuznyechik magma
	dkms remove $(package)/$(version) --all
	rm -rf /usr/src/$(package)-$(version)

modules modules_install clean:
	make -C /lib/modules/$(shell uname -r)/build M=$(shell pwd) $@
