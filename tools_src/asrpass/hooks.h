/*
 *  hooks.h
 *  asrpass
 *
 *  Created by msftguy on 11/2/10.
 *  Copyright 2010 __MyCompanyName__. All rights reserved.
 *
 */

#include <unistd.h>
#include <fcntl.h>

#include <mach-o/dyld.h>

#include <sys/types.h>
#include <sys/uio.h>
#include <sys/ioctl.h>
#include <sys/stat.h>

#include "impHook/impHook.h"

bool hook_api();

