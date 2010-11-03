/*
 *  impHook.h
 *  impHook
 *
 *  Created by msftguy on 6/16/10.
 *  Copyright 2010 __MyCompanyName__. All rights reserved.
 *
 */


#include <stddef.h>
#include <string.h>
#include <mach-o/loader.h>
#include <mach-o/nlist.h>
#include <mach-o/dyld.h>
#include <stdlib.h>
#include <dlfcn.h>
#include <stdio.h>

#include "impHookApi.h"


#ifndef LC_LAZY_LOAD_DYLIB
#define LC_LAZY_LOAD_DYLIB  0x20
#endif
#ifndef S_LAZY_DYLIB_SYMBOL_POINTERS
#define S_LAZY_DYLIB_SYMBOL_POINTERS  0x10
#endif

#if __LP64__
#define LC_SEGMENT_COMMAND			LC_SEGMENT_64
#define LC_ROUTINES_COMMAND			LC_ROUTINES_64
typedef struct mach_header_64		macho_header;
typedef struct section_64			macho_section;
typedef struct nlist_64				macho_nlist;
typedef struct segment_command_64	macho_segment_command;
#else
#define LC_SEGMENT_COMMAND		LC_SEGMENT
#define LC_ROUTINES_COMMAND		LC_ROUTINES
typedef struct mach_header		macho_header;
typedef struct section			macho_section;
typedef struct nlist			macho_nlist;
typedef struct segment_command	macho_segment_command;
#endif
