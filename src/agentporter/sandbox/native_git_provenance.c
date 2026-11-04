/* Loaded only by the fixed trusted update-ref child. Pass actual opened inode
 * capabilities to its publisher before returning from libc open, never paths. */
#define _GNU_SOURCE
#include <dlfcn.h>
#include <errno.h>
#include <fcntl.h>
#include <stdarg.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

static __thread int inside;
static int owned_flags[65536];
static void bind_fd(int fd, int flags, char phase) {
    if (fd < 0 || inside || (flags & O_ACCMODE) == O_RDONLY) return;
    inside = 1;
    const char *setting = getenv("AGENTPORTER_NATIVE_SOCKET");
    if (!setting) _exit(126);
    int channel = atoi(setting);
    char proc[64], path[4096];
    int count = snprintf(proc, sizeof(proc), "/proc/self/fd/%d", fd);
    if (count <= 0 || count >= (int)sizeof(proc)) _exit(126);
    ssize_t size = readlink(proc, path, sizeof(path)-1);
    if (size < 0 || size >= (ssize_t)sizeof(path)-1) _exit(126);
    path[size] = 0;
    const char *prefix = "/workspace/.git/";
    if (!strncmp(path, prefix, strlen(prefix))) {
        const char *relative = path + strlen(prefix);
        if (!strncmp(relative, "refs/", 5) || !strncmp(relative, "logs/refs/", 10) || !strcmp(relative,"packed-refs.lock")) {
            char packet[8192];
            int length = snprintf(packet,sizeof(packet),"%c:%d:%s",phase,flags,relative);
            if (length <= 0 || length >= (int)sizeof(packet)) _exit(126);
            struct iovec io = {.iov_base=packet,.iov_len=(size_t)length};
            char control[CMSG_SPACE(sizeof(int))] = {0};
            struct msghdr message = {.msg_iov=&io,.msg_iovlen=1,.msg_control=control,.msg_controllen=sizeof(control)};
            struct cmsghdr *header = CMSG_FIRSTHDR(&message);
            header->cmsg_level=SOL_SOCKET;header->cmsg_type=SCM_RIGHTS;header->cmsg_len=CMSG_LEN(sizeof(int));
            memcpy(CMSG_DATA(header),&fd,sizeof(fd));
            if (sendmsg(channel,&message,MSG_NOSIGNAL) != length) _exit(126);
            char ack;
            if (recv(channel,&ack,1,0) != 1 || ack != '1') _exit(126);
        }
    }
    inside = 0;
}
#define WRAP_OPEN(NAME) \
int NAME(const char *path, int flags, ...) { \
    mode_t mode=0; if(flags & O_CREAT){va_list ap;va_start(ap,flags);mode=va_arg(ap,int);va_end(ap);} \
    int (*real)(const char*,int,...)=dlsym(RTLD_NEXT,#NAME); \
    int fd; if((flags&O_CREAT) && !(flags&O_EXCL) && strstr(path,"logs/refs/")){fd=real(path,flags|O_EXCL,mode);if(fd>=0)flags|=O_EXCL;else if(errno==EEXIST)fd=real(path,flags,mode);}else fd=real(path,flags,mode);int saved=errno;if(fd>=0 && fd<65536)owned_flags[fd]=flags|0x40000000;bind_fd(fd,flags,'o');errno=saved;return fd; \
}
#define WRAP_OPENAT(NAME) \
int NAME(int parent,const char *path,int flags,...) { \
    mode_t mode=0;if(flags & O_CREAT){va_list ap;va_start(ap,flags);mode=va_arg(ap,int);va_end(ap);} \
    int (*real)(int,const char*,int,...)=dlsym(RTLD_NEXT,#NAME); \
    int fd; if((flags&O_CREAT) && !(flags&O_EXCL) && strstr(path,"logs/refs/")){fd=real(parent,path,flags|O_EXCL,mode);if(fd>=0)flags|=O_EXCL;else if(errno==EEXIST)fd=real(parent,path,flags,mode);}else fd=real(parent,path,flags,mode);int saved=errno;if(fd>=0 && fd<65536)owned_flags[fd]=flags|0x40000000;bind_fd(fd,flags,'o');errno=saved;return fd; \
}
WRAP_OPEN(open)
WRAP_OPEN(open64)
WRAP_OPENAT(openat)
WRAP_OPENAT(openat64)

int close(int fd) {
    int (*real)(int)=dlsym(RTLD_NEXT,"close");
    if(fd>=0 && fd<65536 && owned_flags[fd]){
        int flags=owned_flags[fd]&~0x40000000;owned_flags[fd]=0;
        bind_fd(fd,flags,'c');
    }
    return real(fd);
}
