#include <err.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/mman.h>
#include <unistd.h>

#include "mydev.h"

#define BUFSIZE (1 << 16)

typedef struct mmap_req_user {
	void * __capability addr;    // needs to be null on request. No hints possible for now
	size_t len;
	int prot;
	int flags;
	int fd;
	off_t pos;
	void * __capability extra;
 } mmap_req_user_t;

typedef struct cap_req {
    void* __capability user_cap;
} cap_req_t;

typedef struct {
	char	buf[BUFSIZE + 1];
	size_t	len;
	int identifier;
} foo_t;

typedef struct {
	int identifier;
	int identifier2;
	char cur_char;
} test_t;

int fd;

uint8_t* buffer;

void print_bytes_hex(const uint8_t *bytes, size_t len) {
    for (size_t i = 0; i < len; i++) {
        printf("%02x ", bytes[i]);
    }
    printf("\n");
}

int custom_fd;
#define MODMAPIOC_MAP	_IOWR('a', 1, mmap_req_user_t)

void *custom_map_device(){
	void *addr;

	custom_fd = open("/dev/modmap", O_RDWR);
	if(custom_fd < 0)
		return NULL;

	mmap_req_user_t map_req;
	map_req.addr = NULL;
	map_req.prot = PROT_READ | PROT_WRITE;
	map_req.flags = MAP_ANON | MAP_PRIVATE;
	map_req.fd = -1;
	map_req.pos = 0;
	map_req.len = 4096;

	cap_req_t cap_req;
	cap_req.user_cap = malloc(4096);

	map_req.extra = (void * __capability)(&cap_req);

	int err = ioctl(custom_fd, MODMAPIOC_MAP, &map_req);
	if(err != 0){
		printf("Error From Modmap: %d\n", err);
		return NULL;
	}

	return map_req.addr;
}

void *map_device_memory()
{
    void *addr;
    
    fd = open("/dev/mydev", O_RDWR);
    if (fd < 0)
        return NULL;
    
    addr = mmap(NULL, sizeof(uint8_t)*100, PROT_READ | PROT_WRITE, 
                MAP_SHARED, fd, 0);
    
    /* Keep the fd open while using the mapping */
    /* close(fd) when done */
    
    if (addr == MAP_FAILED)
        return NULL;
        
    return addr;
}

int
main(int argc, char *argv[])
{
	void* void_ptr = map_device_memory();

	void* addr_test = custom_map_device();
	printf("New PTR: %#p\n", addr_test);
	close(custom_fd);

    uint8_t* byte_arr = (uint8_t*)void_ptr;


    print_bytes_hex(byte_arr,100);

	
    bar_t bar; 

    if(void_ptr == NULL){

        printf("map failed\b");
        exit(-1);
    }

    int* root = (int*)malloc(sizeof(int));

    test_struct_t ts;
    ts.ptr_test = root;
    *(ts.ptr_test) = 0x1234;

    int* copy = ts.ptr_test;

    printf("User ptr: %#p\n", ts.ptr_test);
    if(ioctl(fd, MYDEVIOC_TEST, &ts) != 0){
    	printf("failed test ioctl\n");
	exit(-1);
    }

    printf("Mem Checks\n");
    printf("do we root: %x\n", *(root));
    printf("do we: %x\n", *(copy));
    printf("shouldn't get here: %x\n", *(ts.ptr_test));

//    if (ioctl(fd, MYDEVIOC_READ,&bar) != 0)
//	err(1, "ioctl(MYDEVIOC_READ)");

//    printf("Sizeof: %lu, Char: %c, Ident: %x, Ident2: %x\n",sizeof(test_t), test_ptr->cur_char, test_ptr->identifier, test_ptr->identifier2);
    
	close(fd);

	return (0);
}
