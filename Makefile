#KERNEL_SRC_DIR = /usr/src/linux
KERNEL_SRC_DIR = /lib/modules/`uname -r`/build
#EXTRA_CFLAGS = --verbose
VERSION=

obj-m += fmem$(VERSION).o
fmem$(VERSION)-objs := lkm.o 

all:	clean fmem$(VERSION)

fmem$(VERSION) : clean
	make -C $(KERNEL_SRC_DIR) SUBDIRS=`pwd` modules

install:
	./run.sh

deinstall:
	rmmod fmem

clean : 
	rm -f *.o *.ko *.mod.c Module.symvers Module.markers modules.order \.*.o.cmd \.*.ko.cmd \.*.o.d
	rm -rf \.tmp_versions
