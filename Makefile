obj-m := lsm.o
lsm-objs := phdlsm_main.o

KERNELDIR ?= /lib/modules/$(shell uname -r)/build

#PWD       := $(shell pwd)

all:
	$(MAKE) -C $(KERNELDIR) M=$(CURDIR) modules

clean:
	$(MAKE) -C $(KERNELDIR) M=$(CURDIR) clean
