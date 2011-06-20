#!/usr/bin/python
import os
import sys
import mmap
import struct

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
    load_addr = struct.unpack_from("<L", ibss, 0x20)[0] & ~0xff
    print "iBSS/iBEC load addr is 0x%X" % load_addr
    return load_addr
    
def ibxx_locate_bl(ibss):
    kc_printf_arg = "kernelcache prepped at address 0x%"
    printf_arg_loc = byte_search(ibss, kc_printf_arg)
    if printf_arg_loc < 0:
        raise Exception("Could not locate the printf argument (%s)!" % kc_printf_arg)
    baseaddr = ibxx_load_addr(ibss)
    printf_arg_xref = byte_search(ibss, struct.pack("<L", baseaddr + printf_arg_loc))
    if printf_arg_xref < 0:
        raise Exception("Could not locate any xrefs to '%s' string!" % kc_printf_arg)
    # pattern search up until we can find the second BL instruction
    # BL pattern is xx Fx xx F8+
    max_search = 0x100
    mask = 0xF800FF00
    instr = 0xF800F000
    bl_found = 0
    for i in range(printf_arg_xref, printf_arg_xref - max_search, -2):
        dw = struct.unpack_from("<L", ibss, i)[0]
        if dw & mask == instr:
            bl_found += 1
            if bl_found == 2:
                break
    if bl_found != 2:
        raise Exception("Could not find a printf call in the vicinity of string xref :-(")
    print "printf call located at 0x%X (0x%X VA)" % (i, i + baseaddr)
    return i
        
        

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
    magic = 0xDEADB33F
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
    
    
