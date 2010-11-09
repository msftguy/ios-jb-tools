AR = ar
CP = cp
ARMAS = arm-elf-as
OBJCOPY = arm-elf-objcopy
UNAME := $(shell uname -s)
INCLUDE = -I./../..

all:
	$(ARMAS) -mthumb -o ibss_patchproc.o ibss_patchproc.s 
	$(OBJCOPY) -O binary ibss_patchproc.o ibss_patchproc.bin
	
clean:
	rm -rf *.o *.bin
