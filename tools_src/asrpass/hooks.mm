/*
 *  hooks.cpp
 *  asrpass
 *
 *  Created by msftguy on 11/2/10.
 *  Copyright 2010 __MyCompanyName__. All rights reserved.
 *
 */

#include "main.h"

int my_open(const char* path, int flags)
{
	fprintf(stderr, "my_open(%s)\n", path);
	fflush(stderr);
	return open(g_asrRamdisk, flags);
}

int my_ioctl(int fd, unsigned long op, void* a3)
{
	const size_t BLOCKSIZE = 0x1000;
	switch (op) {
		case 0x40046418://get block size
			fprintf(stderr, "my_ioctl(block_size)\n");
			fflush(stderr);
			*(int*)a3 = BLOCKSIZE;
			break;
		case 0x40086419://block count
			{
				struct stat st;
				fstat(fd, &st);
				int blockCount = st.st_size / BLOCKSIZE;
				fprintf(stderr, "my_ioctl(block_count) = 0x%X\n", blockCount);
				fflush(stderr);
				*(int64_t*)a3 = blockCount;
			}
			break;
		default:
			fprintf(stderr, "Unexpected IOCTL code 0x%lX, bailing!\n", op);
			fflush(stderr);
			exit(1);
			break;
	}
	return 0;
}

ssize_t my_pread(int fd, void* buf, size_t size, off_t offset)
{
	return pread(fd, buf, size, offset);
}

const void* my_CFDataGetBytePtr(CFDataRef ref)
{
    const void* result = CFDataGetBytePtr(ref);
    if (result != nil) {
        fprintf(stderr, "Plat: %s\n", (char*)result);
        fflush(stderr);
    }
    return result;
}

bool hook_api() 
{
	const char* moduleName = "asr";
	const mach_header* mh = NULL;
	
	for (int i = 0; i < _dyld_image_count(); ++i) {
		if (NULL != strstr(_dyld_get_image_name(i), moduleName)) {
			mh = _dyld_get_image_header(i);
			//log_progress("%s module found at %p", moduleName, mh);
			break;
		}
	}
	if (mh == NULL) {
		return NO;
	}
	
	
	uintptr_t* pOpenImp = get_import_ptr(mh, "_open");
	uintptr_t* pIoctlImp = get_import_ptr(mh, "_ioctl");
	uintptr_t* pPreadImp = get_import_ptr(mh, "_pread");
	uintptr_t* pCFDataGetBytePtr = get_import_ptr(mh, "_CFDataGetBytePtr");
	
	*pOpenImp = (uintptr_t)my_open;
	*pIoctlImp = (uintptr_t)my_ioctl;
	*pPreadImp = (uintptr_t)my_pread;
    *pCFDataGetBytePtr=(uintptr_t)my_CFDataGetBytePtr;
    
	fprintf(stderr, "ASR io hooked!\n");
	fflush(stderr);
	return YES;
}