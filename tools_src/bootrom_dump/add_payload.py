#!/usr/bin/python
import os
import sys
import mmap
import struct

load_addr = 0

def mmap_file_ro(filename):
    return mmap.mmap(os.open(filename, os.O_RDONLY),
                     0, access=mmap.ACCESS_READ)

def mmap_file_rw(filename):
    return mmap.mmap(os.open(filename, os.O_RDWR),
                     0, access=mmap.ACCESS_WRITE)
    
def ibss_default_patches(origIbss, patchedIbss):
    origFile = open(origIbss, "rb")
    newFile = open(patchedIbss, "wb")
    newFile.write(origFile.read())
    newFile.close()
    ibss = mmap_file_rw(patchedIbss)
    return ibss

def ibxx_load_addr(ibss):
    # load addr+ some small value at 0x20, discard the lsb
    global load_addr
    if load_addr == 0:
        load_addr = struct.unpack_from("<L", ibss, 0x20)[0] & ~0xff
    
        print "iBSS/iBEC load addr is 0x%X" % load_addr
    return load_addr

def pattern_search(bin, offs, pattern, mask, length, dir, step):
    if dir < 0:
        dir = -1
    else:
        dir = 1
    step = abs(step)
    if offs + dir * length < 0:
        length = offs
    if offs + dir * length > len(bin):
        length = len(bin) - offs        
    for i in range(offs, offs + dir * length, dir * step):
        dw = struct.unpack_from("<L", bin, i)[0]
        if dw & mask == pattern:
            return i
    return -1

def bl_search_up(bin, start_addr, len):
    # BL pattern is xx Fx xx F8+
    return pattern_search(bin, start_addr, 0xD000F000, 0xD000F800, len, -1, 2)

def bl_search_down(bin, start_addr, len):
    # BL pattern is xx Fx xx F8+
    return pattern_search(bin, start_addr, 0xD000F000, 0xD000F800, len, 1, 2)

def ldr_search_up(bin, start_addr, len):
    # LDR pattern is xx xx 48 xx ( 00 00 f8 00 )
    return pattern_search(bin, start_addr, 0x00004800, 0x0000F800, len, -1, 2)


def ldr32_search_up(bin, start_addr, len):
    # LDR32 pattern is DF F8 xx xx
    return pattern_search(bin, start_addr, 0x0000F8DF, 0x0000FFFF, len, -1, 2)

def locate_ldr_xref(bin, xref_target):
    # Search for Thumb-2 4-byte LDR first
    i = xref_target
    min_addr = xref_target - 0x1000
    baseaddr = ibxx_load_addr(ibss)
    while True:
        i = ldr32_search_up(bin, i, i - min_addr)
        if i < 0:
            break
        dw = struct.unpack_from("<L", bin, i)[0]
        ldr_target = ((i + 4) & ~3) + ((dw >> 16) & 0xfff)
        if ldr_target == xref_target:
            return i
        i -= 4
    
    # Now search for Thumb-1 LDR
    i = xref_target
    min_addr = xref_target - 0x420
    while True:
        i = ldr_search_up(bin, i, i - min_addr)
        if i < 0:
            print "ldr_search_up(0x%x->0x%x), fail" % (i, i - min_addr)
            return -1
        dw = struct.unpack_from("<L", bin, i)[0]
        ldr_target = ((i + 4) & ~3) + ((dw & 0xff) << 2)
        if ldr_target == xref_target:
            return i
        i -= 2

def ibxx_locate_bl(ibss):
    rd_printf_arg = "creating ramdisk at 0x%x of size 0x%x, from image at 0x%x"
    printf_arg_loc = byte_search(ibss, rd_printf_arg)
    if printf_arg_loc < 0:
        rd_printf_arg = "loaded ramdisk at 0x%x of size 0x%x, from image at 0x%x"
        printf_arg_loc = byte_search(ibss, rd_printf_arg)
        if printf_arg_loc < 0:
            raise Exception("Could not locate the printf argument (%s)!" % rd_printf_arg)
    baseaddr = ibxx_load_addr(ibss)
    print "String '%s' found at 0x%X (0x%X VA)" % (rd_printf_arg, printf_arg_loc, baseaddr + printf_arg_loc)
    printf_arg_xref = byte_search(ibss, struct.pack("<L", baseaddr + printf_arg_loc))
    if printf_arg_xref < 0:
        raise Exception("Could not locate any xrefs to '%s' string!" % rd_printf_arg)

    print "xref1 at 0x%X (0x%X VA)" % (printf_arg_xref, baseaddr + printf_arg_xref)
    xr_ldr = locate_ldr_xref(ibss, printf_arg_xref)
    if xr_ldr < 0:
        raise Exception("Could not find an LDR instruction using string xref :-(")
    print "xref2 at 0x%X (0x%X VA)" % (xr_ldr, baseaddr + xr_ldr)
    printf_bl = bl_search_down(ibss, xr_ldr, 0x30)
    if printf_bl < 0:
        raise Exception("Could not find a printf call after LDR instruction :-(")      
    print "printf call at 0x%X (0x%X VA)" % (printf_bl, printf_bl + baseaddr)
    return printf_bl

def ibss_add_kpf(ibss, kpfFile):
    kpf = open(kpfFile, "rb").read()
    kpf_base = 0xFC
    ibss.seek(kpf_base)
    ibss.write(kpf)
    bl_loc = ibxx_locate_bl(ibss)
    if bl_loc == 0:
        raise Exception("Could not locate the printf call; update the pattern!")
    after_call_loc = bl_loc + 4
    bl_range = (kpf_base - after_call_loc) / 2
    bitmask_11 = ((1 << 11) - 1)
    imm10 = bl_range >> 11
    if imm10 >= (1 << 10):
        raise Exception("Branch out of range!")
    imm10 = imm10 & (bitmask_11 >> 1) #lose extra sign bits
    imm11 = bl_range & bitmask_11
    bl_instr_low = 0xF400 | imm10
    bl_instr_high = 0xF800 | imm11
    struct.pack_into("<HH", ibss,
                     after_call_loc - 4, bl_instr_low, bl_instr_high)
    
def byte_search(image, bytes, step=1):
    for i in range(0, len(image) - len(bytes), step):
	if image[i:i+len(bytes)] == bytes:
		return i
    return -1

def ibxx_set_bootrom_addr(ibss, addr):
    magic = 0xBBBBADDD
    magic_at = byte_search(ibss, struct.pack("<L", magic))
    if magic_at < 0:
        raise Exception("Proc doesn't contain the magic %x" % magic)

    struct.pack_into("<L", ibss, magic_at, addr)
    print "Boot room base address set to %x" % addr

if __name__ == '__main__':
	if len(sys.argv) < 5:
		print "Usage: %s ibss_decrypted_orig ibss_out ibss_patchproc.bin bootrom_addr" % sys.argv[0]
		exit(1)
	ibss = ibss_default_patches(sys.argv[1], sys.argv[2])
	ibss_add_kpf(ibss, sys.argv[3])
	ibxx_set_bootrom_addr(ibss, int(sys.argv[4], 16))
