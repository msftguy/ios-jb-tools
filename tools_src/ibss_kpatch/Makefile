AR = ar
CP = cp
#Macports:
ARMAS = arm-elf-as
#Fink:
#ARMAS = arm-linux-as
OBJCOPY = arm-elf-objcopy
UNAME := $(shell uname -s)
INCLUDE = -I./../..

all:
	$(ARMAS) -mthumb -march=armv6 -o ibss_patchproc.o ibss_patchproc.s 
	$(OBJCOPY) -O binary ibss_patchproc.o ibss_patchproc.bin
	# To avoid confusion..
	rm ibss_patchproc.o	
clean:
	rm -rf *.o *.bin
