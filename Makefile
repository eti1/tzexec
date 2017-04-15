# If KERNELRELEASE is defined, we've been invoked from the
# kernel build system and can use its language.
ifneq ($(KERNELRELEASE),)
        obj-m := tzexec.o
# Otherwise we were called directly from the command
# line; invoke the kernel build system.
else
        #KERNEL_DIR ?= /home/android2/android/system/kernel/samsung/msm8930-common/
        #BUILD_DIR ?= /home/android2/android/system/kernel/samsung/msm8930-common/

	KERNEL_DIR ?= /home/android2/android/system/out/target/product/huashan/obj/KERNEL_OBJ
	BUILD_DIR ?= /home/android2/android/system/out/target/product/huashan/obj/KERNEL_OBJ

        PWD := $(shell pwd)
default:
	$(MAKE) -C $(KERNEL_DIR) O=$(BUILD_DIR) M=$(PWD) ARCH=arm CROSS_COMPILE="arm-linux-androideabi-" modules
endif
