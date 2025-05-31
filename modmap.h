#ifndef _MODMAP_H_
#define _MODMAP_H_

#include <sys/types.h>
#include <sys/ioccom.h>
#include <sys/syscallsubr.h>

struct mmap_req_hook {
	void * __kerncap addr;
	size_t len;
	int prot;
	int flags;
	int fd;
	off_t pos;
	void * __kerncap extra;
 };

struct cap_req {
    void* __capability user_cap;
}

#define MODMAPIOC_MAP	_IORW('a', 1, struct mmap_req_hook)
#endif 
