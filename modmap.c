#include <sys/types.h>
#include <sys/param.h>
#include <sys/conf.h>
#include <sys/systm.h>
#include <sys/kernel.h>
#include <sys/module.h>
#include <sys/malloc.h>
#include <sys/uio.h>
#include <vm/vm.h>
#include <vm/pmap.h>
#include <machine/bus.h>  /* For BUS_SPACE_MAXADDR constants */
#include <cheri/cheric.h>
#include <sys/proc.h>

#include "modmap.h"

#define BUFSIZE (1 << 16)

MALLOC_DECLARE(M_MODMAP);
MALLOC_DEFINE(M_MODMAP, "modmap", "modified mmap device");


static d_open_t		modmap_open;
static d_close_t	modmap_close;
static d_read_t		modmap_read;
static d_write_t	modmap_write;
static d_ioctl_t	modmap_ioctl;
static int		modmap_modevent(module_t, int, void *);

static struct cdevsw modmap_cdevsw = {
	.d_name		= "modmap",
	.d_version	= D_VERSION,
	.d_flags	= D_TRACKCLOSE,
	.d_open		= modmap_open,
	.d_close	= modmap_close,
	.d_read		= modmap_read,
	.d_write	= modmap_write,
	.d_ioctl	= modmap_ioctl,
};

static struct cdev *modmap_cdev;

static int
modmap_open(struct cdev *dev, int flags, int devtype, struct thread *td)
{
	uprintf("modmap: device opened\n");
	return (0);
}

static int
modmap_close(struct cdev *dev, int flags, int devtype, struct thread *td)
{
	uprintf("modmap: device closed\n");
	return (0);
}

static int
modmap_read(struct cdev *dev, struct uio *uio, int ioflag)
{
    uprintf("MODMAP: Read Not Allowed\n");
	return EINVAL;
}

static int
modmap_write(struct cdev *dev, struct uio *uio, int ioflag)
{
    uprintf("MODMAP: Write Not Allowed\n");
    return EINVAL;
}



static int
modmap_ioctl(struct cdev *dev, u_long cmd, caddr_t addr, int flags,
    struct thread *td)
{
    uprintf("In Modmap Ioctl\n");
    mmap_req_user_t* kern_req_user;

    struct cap_req* user_cap_req;
    struct cap_req kern_cap_req;

    int error = 0;

    mmap_req_hook_t kern_req;

	switch (cmd) {
        case MODMAPIOC_MAP:
            kern_req_user = (mmap_req_user_t *)addr;

            if(kern_req_user->addr != NULL){
                error = EINVAL;
                break;
            }

            user_cap_req = (struct cap_req*)kern_req_user->extra;
            
            kern_req.addr = NULL;
	        kern_req.len = kern_req_user->len;
	        kern_req.prot = kern_req_user->prot;
	        kern_req.flags = kern_req_user->flags;
	        kern_req.fd = kern_req_user->fd;
	        kern_req.pos = kern_req_user->pos;
	        kern_req.extra = NULL;

            error = copyin(user_cap_req, &kern_cap_req, sizeof(kern_cap_req));
            if(error != 0)
                break;

            kern_req.extra = (void * __kerncap)(&kern_cap_req);
            
            error = kern_mmap_hook(td, &kern_req);
            if(error != 0){
                uprintf("Error From mmap: %d\n", error);
                break;
            }

            void * __kerncap mapped_addr = (void * __kerncap)td->td_retval[0];

            kern_req_user->addr = kern_req.addr;
            kern_req_user->len = kern_req.len;
            kern_req_user->prot = kern_req.prot;
            kern_req_user->flags = kern_req.flags;
            kern_req_user->fd = kern_req.fd;
            kern_req_user->pos = kern_req.pos;
            kern_req_user->extra = NULL;

            uprintf("First Copyoutcap\n");
            error = copyoutcap(&mapped_addr, &(kern_req_user->addr), sizeof(void *));
            if(error != 0){
                uprintf("Here's the addr: %p\n", kern_req.addr);
                uprintf("Copuoutcap error: %d\n", error);
                break;
            }

            uprintf("Here's success addr: %p\n", kern_req_user->addr);

            uprintf("First Copyout\n");
            error = copyout(&kern_cap_req, kern_req_user->extra, sizeof(kern_cap_req));
            if(error != 0)
                break;

            break;
        default:
            error = ENOTTY;
            break;
	}

	return (error);
}

uint8_t* buffer;

static int
modmap_modevent(module_t mod, int type, void *arg)
{
	int error = 0;

	switch (type) {
	case MOD_LOAD:
		modmap_cdev = make_dev(&modmap_cdevsw, 0, UID_ROOT, GID_WHEEL,
		    0666, "modmap");
		break;
	case MOD_UNLOAD: /* FALLTHROUGH */
	case MOD_SHUTDOWN:
		destroy_dev(modmap_cdev);
		break;
	default:
		error = EOPNOTSUPP;
		break;
	}

	return (error);
}

DEV_MODULE(modmap, modmap_modevent, NULL);
