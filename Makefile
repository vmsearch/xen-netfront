obj-m := xen-netfront_hotfix.o
KERNEL = /lib/modules/`uname -r`/build
PWD = $(shell pwd)
modules:
	make -C ${KERNEL} M=`pwd` modules
clean:
	rm -rf *.o *~ core .depend .*.cmd *.ko *.mod.c .tmp_versions
