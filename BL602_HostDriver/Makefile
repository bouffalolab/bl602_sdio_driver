BL_VERS_NUM=5.5.0.0

CONFIG_BL_FULLMAC ?= m

KERNELVERSION := 	$(shell uname -r)

subdir-ccflags-$(CONFIG_DEBUG_FS) += -DCONFIG_BL_DEBUGFS
subdir-ccflags-y += -I$(src)/fullmac

# FW VARS
subdir-ccflags-y += -DNX_VIRT_DEV_MAX=4
subdir-ccflags-y += -DNX_REMOTE_STA_MAX=10
subdir-ccflags-y += -DNX_CHAN_CTXT_CNT=3

obj-$(CONFIG_BL_FULLMAC) += fullmac/

#KERNELDIR = ~/Workspace/linux-4.10
#KERNELDIR ?= /lib/modules/$(KERNELVERSION)/build
KERNELDIR=/home/gitadmin03/yzy/T31/ISVP-T31-1.1.2-20201021/software/sdk/Ingenic-SDK-T31-1.1.2-20201021/opensource/kernel

all: modules

modules clean:
	@$(PWD)/mklink.sh
	$(MAKE) -C $(KERNELDIR) O=$(KBUILDDIR) M=$(PWD) $@
	@$(PWD)/mklink.sh clean

