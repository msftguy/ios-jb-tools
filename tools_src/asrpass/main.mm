//
//  main.m
//  asrpass
//
//  Created by msftguy on 11/2/10.
//  Copyright 2010 __MyCompanyName__. All rights reserved.
//

#include "main.h"

const char* g_asrRamdisk;
const char* g_asrPlat;

extern "C" void dlentry();
void dlentry()
{
	g_asrRamdisk = getenv("ASR_RAMDISK");
	if (g_asrRamdisk == NULL) {
		fprintf(stderr, "ASR_RAMDISK envvar not set!\n");
		fflush(stderr);
		exit(1);
	}
	
	const char* getpass_proc = getenv("ASR_GETPASS_PROC");
	if (getpass_proc == NULL) {
		fprintf(stderr, "ASR_GETPASS_PROC envvar not set!\n");
		fflush(stderr);
		exit(1);
	}
    g_asrPlat = getenv("ASR_PLATFORM");
	CFStringRef (*getpass_fn)();
	typedef CFStringRef (*getpass_fn_t)();
    char* ptr = nil;
	if (!sscanf(getpass_proc, "%p", &ptr) ) {
		fprintf(stderr, "ASR_GETPASS_PROC envvar must be a hex number!\n");
		fflush(stderr);	
		exit(1);
	}
    ptr += _dyld_get_image_vmaddr_slide(0);
    getpass_fn = (getpass_fn_t)ptr;
    fprintf(stderr, "ASR_GETPASS_PROC is at %p\n", getpass_fn);
    fflush(stderr);		
    hook_api();
    CFStringRef passphrase = getpass_fn();
	char passBuf[0x100];
	CFStringGetCString(passphrase, passBuf, sizeof(passBuf), kCFStringEncodingASCII);
	fprintf(stderr, "Passphrase: %s\n", passBuf);
	fflush(stderr);
	exit(0);
}
