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

def ibss_add_kpf(ibss, kpfFile):
    kpf = open(kpfFile, "rb").read()
    kpf_base = 0xFC
    ibss.seek(kpf_base)
    ibss.write(kpf)
    #pattern match: bytes immediately after the BL to printf with kernel addr
    after_call_loc = byte_search(ibss, "\x30\x46\x00\x21\x42\x46")
    if after_call_loc < 0:
        raise Exception("Could not locate the printf call; update the pattern!")
    print "BL at %X" % (after_call_loc - 4)
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
    for i in range(0, len(ibss), 4):
        dw = struct.unpack_from("<L", ibss, i)[0]
        if dw == 0xdeadf00d:
            print "Magic found at %X" % i
            for p in kpatches:
                struct.pack_into("<LL", ibss, i, p, kpatches[p])
                i += 8
            return
    raise Exception("Magic not found in ibss!")

def byte_search(image, bytes):
    for i in range(0, len(image) - len(bytes), 2):
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
    
    
