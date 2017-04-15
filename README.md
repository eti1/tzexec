# Disable baseband signature check in trustzone
I wanted to patch the baseband firmware running on my phone (based on Qualcomm MSM8960). 
(ie. /etc/firmware/modem.\*).

This is normally not possible, as these firmware images must be properly signed to be allowed to run. 
If you patch those images and try to run it, pas\_init\_image will just fail and return -2.
The signature checking is enforced in the TrustZone code (partition TZ or Aboot dependign on vendor).

This project provides a way to bypass this signature checking, by abusing a bug documented by Dan Rosenberg in 2014 (see docs/\*.pdf).

# Compiling
To use this, you will need to add this module to your android kernel (I just set it to run first when my kernel boots).
It contains symbols for the Sony Xperia SP (huashan) and the Samsung Galaxy Ace 3 (s7275r).

To build it, I assume you already know how to compile the kernel for your platform.
I encourage you to read tzexec.c to understand a bit about what is going on.

## Samsung Galaxy Ace 3
You just need tzexec module. It will patch two bytes in tz memory and that's all you need.

Copy/symlink tzexec.{c,h} in arch/arm/mach-msm/

In tzexec.c, define SAMSUNG\_ACE\_3, and undefine SONY\_XPERIA\_SP 

In arch/arm/mach-msm/Makefile, add the line "obj-y += tzexec.o" before scm.o

Compile and run, cross your fingers, check kernel messages to ensure it worked.

## Sony Xperia SP
The trustzone implementation is a bit different, and the method of patching two bytes is not enought there.
I used a different method, and re-implemented the image loading in non-secure world.
So you'll also need to apply the patch mach-msm.patch to call it instead of the trustzone version.

Next, just follow the same steps as for Samsung (just define SONY\_XPERIA\_SP instead of SAMSUNG\_ACE\_3).

Same-same: check kernel logs for success.

## Running
This exploit disables the signature checking only, bute the image still need to contain the proper segment's hashes. 

To run arbitrary firmware images, just patch the things you want, correct the hash segment, and there you are. 
You can use [pymdt](https://github.com/eti1/pymdt) to do this.
