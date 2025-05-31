#ifndef _MODMAP_H_
#define _MODMAP_H_

#include <sys/types.h>
#include <sys/ioccom.h>
#include <sys/syscallsubr.h>

typedef struct mmap_req_hook mmap_req_hook_t;

struct cap_req {
    void* __capability user_cap;
};

#define MODMAPIOC_MAP	_IOWR('a', 1, struct mmap_req_hook)
#endif 
