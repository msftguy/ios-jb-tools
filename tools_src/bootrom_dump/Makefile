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
	$(ARMAS) -mthumb -march=armv6 -o ibxx_bdproc.o ibxx_bdproc.s 
	$(OBJCOPY) -O binary ibxx_bdproc.o ibxx_bdproc.bin
	# To avoid confusion..
	rm ibxx_bdproc.o	
clean:
	rm -rf *.o *.bin
