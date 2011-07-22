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
    

def diff_kernel(origFile, patchedFile):
    orig = mmap_file_ro(origFile)
    patched = mmap_file_ro(patchedFile)
    
    if len(orig) != len(patched):
        raise Exception("Orig and patched kernels must be of the same size!")

    patch_locations = []
    for i in range(len(orig)):
        if orig[i] != patched[i]:
            rounded_pos = i & ~3
            if not rounded_pos in patch_locations:
                patch_locations.append(rounded_pos)
    patches = {}
    for i in patch_locations:
        patches[i] = struct.unpack_from("<L", patched, i)[0]
    return patches

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

def pattern_search(bin, offs, pattern, mask, len, dir, step):
    if dir < 0:
        dir = -1
    else:
        dir = 1
    step = abs(step)        
    for i in range(offs, offs + dir * len, dir * step):
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
        i -= 4 # Could be 4, but leaving this for when we implement i8 LDRs

    # Now search for Thumb-1 LDR
    i = xref_target
    min_addr = xref_target - 0x400
    while True:
        i = ldr_search_up(bin, i, i - min_addr)
        if i < 0:
            return -1
        dw = struct.unpack_from("<L", bin, i)[0]
        ldr_target = ((i + 4) & ~3) + (((dw >> 16) & 0xff) << 2)
        if ldr_target == xref_target:
            return i
        i -= 2

def ibxx_locate_bl_old(ibss):
    kc_printf_arg = "kernelcache prepped at address 0x%"
    printf_arg_loc = byte_search(ibss, kc_printf_arg)
    if printf_arg_loc < 0:
        raise Exception("Could not locate the printf argument (%s)!" % kc_printf_arg)
    baseaddr = ibxx_load_addr(ibss)
    printf_arg_xref = byte_search(ibss, struct.pack("<L", baseaddr + printf_arg_loc))
    if printf_arg_xref < 0:
        raise Exception("Could not locate any xrefs to '%s' string!" % kc_printf_arg)
    # pattern search up until we can find the second BL instruction
    bl1 = bl_search_up(ibss, printf_arg_xref, len)
    if bl1 < 0:
        raise Exception("Could not locate BL before kc_printf_arg!")
    
    bl2 = bl_search_up(ibss, bl1 - 4, len)
    if bl2 < 0:
        raise Exception("Could not find a printf call in the vicinity of string xref :-(")
    print "printf call located at 0x%X (0x%X VA)" % (bl2, bl2 + baseaddr)
    return bl2

def ibxx_locate_bl(ibss):
    kc_printf_arg = "Uncompressed kernel cache at 0x%"
    printf_arg_loc = byte_search(ibss, kc_printf_arg)
    if printf_arg_loc < 0:
        raise Exception("Could not locate the printf argument (%s)!" % kc_printf_arg)
    baseaddr = ibxx_load_addr(ibss)
    print "String '%s' found at 0x%X (0x%X VA)" % (kc_printf_arg, printf_arg_loc, baseaddr + printf_arg_loc)
    printf_arg_xref = byte_search(ibss, struct.pack("<L", baseaddr + printf_arg_loc))
    if printf_arg_xref < 0:
        raise Exception("Could not locate any xrefs to '%s' string!" % kc_printf_arg)

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
    
    
def ibss_add_kpatches(ibss, kpatches):
    magic = 0xDEADB34F
    for i in range(0, len(ibss), 4):
        dw = struct.unpack_from("<L", ibss, i)[0]
        if dw == magic:
            print "Magic (0x%X) found at 0x%X" % (magic, i)
            struct.pack_into("<L", ibss, i, 0)
            for p in kpatches:
                # check we aren't overwriting anything first
                orig = struct.unpack_from("<LL", ibss, i)
                if (orig[0] | orig[1]) != 0:
                    raise Exception("Too many patches, out of 'free' space at 0x%X" % i)
                struct.pack_into("<LL", ibss, i, p, kpatches[p])
                i += 8
            return
    raise Exception("Magic (0x%X) not found in ibss, ibss_patchproc.bin might be out of date!" % magic)

def byte_search(image, bytes, step=1):
    for i in range(0, len(image) - len(bytes), step):
	if image[i:i+len(bytes)] == bytes:
		return i
    return -1

if __name__ == '__main__':
	if len(sys.argv) < 6:
		print "Usage: ibss_patcher ibss_decrypted_orig ibss_out kernelcache_decrypted_orig kernelcache_decrypted_patched ibss_patchproc.bin"
		exit(1)
	kpatches = diff_kernel(sys.argv[3], sys.argv[4])
	ibss = ibss_default_patches(sys.argv[1], sys.argv[2])
	ibss_add_kpf(ibss, sys.argv[5])
	ibss_add_kpatches(ibss, kpatches)
    
    
