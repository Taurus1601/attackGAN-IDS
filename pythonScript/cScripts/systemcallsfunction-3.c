#define _GNU_SOURCE

#include "systemcallsfunction.h"
#include <time.h>                   // Time functions
#include <pthread.h>                // POSIX threads

// System-related headers
#include <sys/types.h>             // Basic system data types
#include <sys/stat.h>              // File status
#include <sys/time.h>              // Time operations
#include <sys/resource.h>          // Resource operations
#include <sys/wait.h>              // Process control
#include <sys/mman.h>              // Memory management
#include <sys/ioctl.h>             // I/O control
#include <sys/sysinfo.h>           // System statistics
#include <sys/xattr.h>             // Extended attributes
#include <sys/msg.h>               // Message queues
#include <sys/sem.h>               // Semaphores
#include <sys/shm.h>               // Shared memory

// Network-related headers
#include <netinet/in.h>            // Internet protocol
#include <arpa/inet.h>             // Internet operations

// General-purpose headers
#include <fcntl.h>                  // File control operations
#include <unistd.h>                 // UNIX standard functions
#include <stdio.h>                  // Standard I/O
#include <stdlib.h>                 // Standard library functions
#include <string.h>                 // String operations
#include <errno.h>                  // Error number definitions
#include <signal.h>                 // Signal handling
#include <dirent.h>                 // Directory entries
#include <poll.h>  
#include <ucontext.h>
#include <sys/syscall.h>
#include <sys/uio.h>  
#include <sys/mman.h>  
#include <sched.h>
#include <sys/utsname.h> 
#include <sys/times.h>
#include <sys/mount.h>   // For pivot_root, if available
#include <sys/prctl.h>
#include <sys/timex.h>
#include <sys/reboot.h> 
#include <sys/quota.h>
#include <linux/futex.h>
#include <linux/aio_abi.h>



#include <linux/fanotify.h>  // Include the fanotify header
#include <sys/socket.h>

#include <sys/random.h>
#include <netinet/in.h>
#include <linux/fs.h>
#include <linux/seccomp.h>
#include <linux/module.h>
#include <linux/kcmp.h>
#include <linux/limits.h>
#include <sys/vfs.h>
#include <linux/bpf.h>
#include <linux/userfaultfd.h>
#include <linux/membarrier.h>
#include <linux/io_uring.h>

#include <linux/perf_event.h>
#include <sys/statvfs.h>









// Define IO priority constants if not available
#ifndef IOPRIO_CLASS_SHIFT
#define IOPRIO_CLASS_SHIFT 13
#endif

#ifndef IOPRIO_PRIO_VALUE
#define IOPRIO_PRIO_VALUE(class, data) (((class) << IOPRIO_CLASS_SHIFT) | data)
#endif

#ifndef IOPRIO_WHO_PROCESS
#define IOPRIO_WHO_PROCESS 1
#endif

#ifndef IOPRIO_CLASS_BE
#define IOPRIO_CLASS_BE 2
#endif




#ifndef MREMAP_MAYMOVE
#define MREMAP_MAYMOVE 1
#endif
#define STACK_SIZE (1024 * 1024)
//-----------------------clone--------------------
#ifndef CLONE_VM
#define CLONE_VM       0x00000100  // Cloning of the virtual memory
#endif

#ifndef CLONE_FS
#define CLONE_FS       0x00000200  // Cloning of the filesystem information
#endif

#ifndef CLONE_FILES
#define CLONE_FILES    0x00000400  // Cloning of the file descriptors
#endif

#ifndef CLONE_SIGHAND
#define CLONE_SIGHAND  0x00000800  // Cloning of the signal handlers
#endif

#ifndef CLONE_THREAD
#define CLONE_THREAD   0x00010000  // Used for creating a new thread
#endif
//-------------clone------------------
#define SPLICE_F_MOVE 0x01
//-------------------------



// function for template_clone---------------
int thread_function(void *arg) {
    printf("Thread function: PID = %d, PPID = %d\n", getpid(), getppid());
    return 0;
}
//-------------------------------------------------

//---------------modify ldt-----------


struct user_desc {
    unsigned int entry_number;
    unsigned int base_addr;
    unsigned int limit;
    unsigned int seg_32bit:1;
    unsigned int contents:2;
    unsigned int read_exec_only:1;
    unsigned int limit_in_pages:1;
    unsigned int seg_not_present:1;
    unsigned int useable:1;
#ifdef __x86_64__
    unsigned int lm:1;
#endif
};

#define SYS_modify_ldt 123

//-====================================


// Define the system call number and constants if not defined
#ifndef SYS_arch_prctl
#define SYS_arch_prctl 158
#endif

#ifndef ARCH_SET_FS
#define ARCH_SET_FS 0x1002
#endif

#ifndef ARCH_GET_FS
#define ARCH_GET_FS 0x1003
#endif



//================================




// Define the system call numbers if not defined
#ifndef SYS_iopl
#define SYS_iopl 172
#endif

#ifndef SYS_ioperm
#define SYS_ioperm 173
#endif




//=============================================




int futex_wait(int *addr, int val) {
    return syscall(SYS_futex, addr, FUTEX_WAIT, val, NULL, NULL, 0);
}

int futex_wake(int *addr, int count) {
    return syscall(SYS_futex, addr, FUTEX_WAKE, count, NULL, NULL, 0);
}

int futex_lock(int *futex) {
    while (__sync_val_compare_and_swap(futex, 0, 1) != 0) {
        futex_wait(futex, 1);
    }
    return 0;
}

int futex_unlock(int *futex) {
    if (__sync_val_compare_and_swap(futex, 1, 0) != 1) {
        return -1;
    }
    futex_wake(futex, 1);
    return 0;
}

int futex = 0;

void *thread_function_futex(void *arg) {
    printf("Thread %ld: Waiting for lock\n", (long)arg);
    futex_lock(&futex);
    printf("Thread %ld: Acquired lock\n", (long)arg);
    sleep(1);  // Simulate work
    printf("Thread %ld: Releasing lock\n", (long)arg);
    futex_unlock(&futex);
    return NULL;
}




//======================================================


#ifndef FAN_CLOEXEC
#define FAN_CLOEXEC 0x02000000
#endif

#ifndef FAN_CLASS_NOTIF
#define FAN_CLASS_NOTIF 0x00000000
#endif

#ifndef FAN_MARK_ADD
#define FAN_MARK_ADD 0x00000001
#endif

#ifndef FAN_CREATE
#define FAN_CREATE 0x00000100
#endif

#ifndef FAN_DELETE
#define FAN_DELETE 0x00000200
#endif


//=====================================================




// Define syscall if not defined
#ifndef __NR_bpf
#define __NR_bpf 321  
#endif

// Wrapper function for bpf syscall
static int bpf(int cmd, union bpf_attr *attr, unsigned int size) {
    return syscall(__NR_bpf, cmd, attr, size);
}



//===================================================


// read
void template_read() {
    char buffer[100];
    int fd = open("testfil.txt", O_RDONLY);
    if (fd == -1) {
        perror("open");
        return;
    }
    ssize_t bytesRead = read(fd, buffer, sizeof(buffer) - 1);
    if (bytesRead == -1) {
        perror("read");
    } else {
        buffer[bytesRead] = '\0';
        printf("Read %zd bytes: %s\n", bytesRead, buffer);
    }
    close(fd);
}


// write
void template_write() {
    const char *text = "Hello, World!";
    int fd = open("testfil.txt", O_WRONLY | O_CREAT, 0644);
    if (fd == -1) {
        perror("open");
        return;
    }
    ssize_t bytesWritten = write(fd, text, strlen(text));
    if (bytesWritten == -1) {
        perror("write");
    } else {
        printf("Wrote %zd bytes\n", bytesWritten);
    }
    close(fd);
}


// close
void template_close() {
    int fd = open("/tmp/testfile.txt", O_RDONLY);
    if (fd == -1) {
        perror("open");
        return;
    }
    if (close(fd) == -1) {
        perror("close");
    } else {
        printf("File closed successfully\n");
    }
}

// newstat
void template_newstat() {
    struct stat statbuf;
    if (stat("/tmp/testfile.txt", &statbuf) == -1) {
        perror("stat");
    } else {
        printf("File size: %ld bytes\n", statbuf.st_size);
    }
}
void template_newfstat() {
    struct stat statbuf;
    int fd = open("/tmp/testfile.txt", O_RDONLY);
    if (fd == -1) {
        perror("open");
        return;
    }
    if (fstat(fd, &statbuf) == -1) {
        perror("fstat");
    } else {
        printf("File size: %ld bytes\n", statbuf.st_size);
    }
    close(fd);
}

// newlstat
void template_newlstat() {
    struct stat statbuf;
    if (lstat("/tmp/testfile_symlink.txt", &statbuf) == -1) {
        perror("lstat");
    } else {
        printf("File size: %ld bytes\n", statbuf.st_size);
    }
}


// poll
void template_poll() {
    struct pollfd fds[1];
    fds[0].fd = STDIN_FILENO;
    fds[0].events = POLLIN;
    
    int ret = poll(fds, 1, 5000);
    if (ret == -1) {
        perror("poll");
    }
}


// lseek
void template_lseek() {
    int fd = open("/tmp/testfile.txt", O_RDONLY);
    if (fd == -1) {
        perror("open");
        return;
    }
    off_t offset = lseek(fd, 10, SEEK_SET);
    if (offset == -1) {
        perror("lseek");
    } else {
        printf("Seeked to offset %ld\n", offset);
    }
    close(fd);
}

// mmap
void template_mmap() {
    int fd = open("/tmp/testfile.txt", O_RDONLY);
    if (fd == -1) {
        perror("open");
        return;
    }
    struct stat statbuf;
    if (fstat(fd, &statbuf) == -1) {
        perror("fstat");
        close(fd);
        return;
    }
    void *map = mmap(NULL, statbuf.st_size, PROT_READ, MAP_PRIVATE, fd, 0);
    if (map == MAP_FAILED) {
        perror("mmap");
    } else {
        printf("File mapped to memory\n");
        munmap(map, statbuf.st_size);
    }
    close(fd);
}


// mprotect
void template_mprotect() {
    void *addr = malloc(4096);
    if (addr == NULL) {
        perror("malloc");
        return;
    }
    if (mprotect(addr, 4096, PROT_READ | PROT_WRITE) == -1) {
        perror("mprotect");
    } else {
        printf("Memory protection set\n");
    }
    free(addr);
}

// munmap
void template_munmap() {
    void *addr = malloc(4096);
    if (addr == NULL) {
        perror("malloc");
        return;
    }
    if (munmap(addr, 4096) == -1) {
        perror("munmap");
    } else {
        printf("Memory unmapped successfully\n");
    }
    free(addr);
}
void template_brk() {
    void *current_brk = sbrk(0);
    if (current_brk == (void *)-1) {
        perror("sbrk");
        return;
    }
    printf("Current program break: %p\n", current_brk);
    if (brk(current_brk + 4096) == -1) {
        perror("brk");
    } else {
        printf("Program break increased by 4096 bytes\n");
    }
}


// rt_sigaction
void template_rt_sigaction() {
    struct sigaction sa;
    memset(&sa, 0, sizeof(sa));
    sa.sa_handler = SIG_IGN;
    sigemptyset(&sa.sa_mask);
    sa.sa_flags = 0;
    
    if (sigaction(SIGINT, &sa, NULL) == -1) {
        perror("sigaction");
    }
}


// rt_sigprocmask
void template_rt_sigprocmask() {
    sigset_t set;
    sigemptyset(&set);
    sigaddset(&set, SIGINT);
    
    if (sigprocmask(SIG_BLOCK, &set, NULL) == -1) {
        perror("sigprocmask");
    }
}

// rt_sigreturn
void template_rt_sigreturn() {
    printf("Executing rt_sigreturn system call\n");

    // Prepare a ucontext structure to simulate a signal handler context
    ucontext_t context;
    getcontext(&context);

    // Inline assembly to invoke the rt_sigreturn system call
    asm volatile (
        "mov x8, %0\n"  // System call number for rt_sigreturn
        "mov x0, %1\n"  // Pointer to the ucontext structure
        "svc 0\n"       // Make the system call
        :
        : "i" (SYS_rt_sigreturn), "r" (&context)
        : "x0", "x8"
    );
}

void template_ioctl() {
    int fd = open("/dev/null", O_RDONLY);
    if (fd == -1) {
        perror("open");
        return;
    }
    if (ioctl(fd, FIONREAD, NULL) == -1) {
        perror("ioctl");
    } else {
        printf("ioctl executed successfully\n");
    }
    close(fd);
}


// pread64
void template_pread64() {
    char buffer[100];
    int fd = open("/tmp/testfile.txt", O_RDONLY);
    if (fd == -1) {
        perror("open");
        return;
    }
    
    ssize_t bytesRead = pread(fd, buffer, sizeof(buffer) - 1, 0);
    if (bytesRead == -1) {
        perror("pread");
    } else {
        buffer[bytesRead] = '\0';
        printf("Read %zd bytes\n", bytesRead);
    }
    close(fd);
}

// pwrite64
void template_pwrite64() {
    const char *text = "Hello\n";
    int fd = open("/tmp/testfile.txt", O_WRONLY | O_CREAT, 0644);
    if (fd == -1) {
        perror("open");
        return;
    }
    
    ssize_t bytesWritten = pwrite(fd, text, strlen(text), 0);
    if (bytesWritten == -1) {
        perror("pwrite");
    }
    close(fd);
}

// readv
void template_readv() {
    struct iovec iov[2];
    char buf1[10], buf2[10];
    iov[0].iov_base = buf1;
    iov[0].iov_len = sizeof(buf1);
    iov[1].iov_base = buf2;
    iov[1].iov_len = sizeof(buf2);
    
    int fd = open("/tmp/testfile.txt", O_RDONLY);
    if (fd == -1) {
        perror("open");
        return;
    }
    
    ssize_t bytesRead = readv(fd, iov, 2);
    if (bytesRead == -1) {
        perror("readv");
    }
    close(fd);
}


void template_writev() {
    struct iovec iov[2];
    char *buf1 = "Hello ";
    char *buf2 = "World\n";
    iov[0].iov_base = buf1;
    iov[0].iov_len = strlen(buf1);
    iov[1].iov_base = buf2;
    iov[1].iov_len = strlen(buf2);
    
    int fd = open("/tmp/testfile.txt", O_WRONLY | O_CREAT, 0644);
    if (fd == -1) {
        perror("open");
        return;
    }
    
    ssize_t bytesWritten = writev(fd, iov, 2);
    if (bytesWritten == -1) {
        perror("writev");
    }
    close(fd);
}

// access
void template_access() {
    int result = access("/tmp/testfile.txt", F_OK);
    if (result == 0) {
        printf("File exists\n");
    } else {
        perror("access");
    }
}

// pipe
void template_pipe() {
    int pipefd[2];
    if (pipe(pipefd) == -1) {
        perror("pipe");
    } else {
        printf("Pipe created successfully. Read end: %d, Write end: %d\n", pipefd[0], pipefd[1]);
        close(pipefd[0]);
        close(pipefd[1]);
    }
}


// select
void template_select() {
    fd_set readfds;
    struct timeval timeout;
    int fd = open("/tmp/testfile.txt", O_RDONLY);
    if (fd == -1) {
        perror("open");
        return;
    }
    FD_ZERO(&readfds);
    FD_SET(fd, &readfds);
    timeout.tv_sec = 5;
    timeout.tv_usec = 0;
    int ret = select(fd + 1, &readfds, NULL, NULL, &timeout);
    if (ret == -1) {
        perror("select");
    } else if (ret == 0) {
        printf("Select timed out\n");
    } else {
        if (FD_ISSET(fd, &readfds)) {
            printf("Data is available to read\n");
        }
    }
    close(fd);
}

// sched_yield
void template_sched_yield() {
    if (sched_yield() == -1) {
        perror("sched_yield");
    } else {
        printf("Yielded processor\n");
    }
}

void template_mremap() {
    // Allocate initial memory
    void *old_addr = mmap(NULL, 4096, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (old_addr == MAP_FAILED) {
        perror("mmap");
        return;
    }

    // Attempt to remap the memory
    void *new_addr = mremap(old_addr, 4096, 8192, MREMAP_MAYMOVE);
    if (new_addr == MAP_FAILED) {
        perror("mremap");
        munmap(old_addr, 4096); // Ensure old memory is unmapped if remap fails
    } else {
        printf("Memory remapped successfully\n");
    }

    // Unmap the newly allocated address (new_addr)
    if (munmap(new_addr, 8192) == -1) {
        perror("munmap");
    }
}

// msync example
void template_msync() {
    // Allocate memory
    void *addr = mmap(NULL, 4096, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (addr == MAP_FAILED) {
        perror("mmap");
        return;
    }

    // Synchronize memory changes with the underlying storage
    if (msync(addr, 4096, MS_SYNC) == -1) {
        perror("msync");
    } else {
        printf("Memory synchronized successfully\n");
    }

    // Unmap the memory
    if (munmap(addr, 4096) == -1) {
        perror("munmap");
    }
}



void template_mincore() {
    void *addr = malloc(4096);
    if (addr == NULL) {
        perror("malloc");
        return;
    }
    unsigned char vec[1];
    if (mincore(addr, 4096, vec) == -1) {
        perror("mincore");
    } else {
        printf("Memory residency checked successfully\n");
    }
    free(addr);
}

// madvise
void template_madvise() {
    void *addr = malloc(4096);
    if (addr == NULL) {
        perror("malloc");
        return;
    }
    if (madvise(addr, 4096, MADV_NORMAL) == -1) {
        perror("madvise");
    } else {
        printf("Memory advice set successfully\n");
    }
    free(addr);
}

void template_shmget() {
    int shmid = shmget(IPC_PRIVATE, 4096, IPC_CREAT | 0666);
    if (shmid == -1) {
        perror("shmget");
    } else {
        printf("Shared memory segment created successfully\n");
    }
}

// shmat
void template_shmat() {
    int shmid = shmget(IPC_PRIVATE, 4096, IPC_CREAT | 0666);
    if (shmid == -1) {
        perror("shmget");
        return;
    }
    void *shmaddr = shmat(shmid, NULL, 0);
    if (shmaddr == (void *)-1) {
        perror("shmat");
    } else {
        printf("Shared memory attached successfully\n");
        shmdt(shmaddr);
    }
}


// shmctl
void template_shmctl() {
    int shmid = shmget(IPC_PRIVATE, 4096, IPC_CREAT | 0666);
    if (shmid == -1) {
        perror("shmget");
        return;
    }
    if (shmctl(shmid, IPC_RMID, NULL) == -1) {
        perror("shmctl");
    } else {
        printf("Shared memory control operation executed successfully\n");
    }
}

// dup
void template_dup() {
    int fd = open("/tmp/testfile.txt", O_RDONLY);
    if (fd == -1) {
        perror("open");
        return;
    }
    int newfd = dup(fd);
    if (newfd == -1) {
        perror("dup");
    } else {
        printf("File descriptor duplicated successfully\n");
        close(newfd);
    }
    close(fd);
}
// dup2
void template_dup2() {
    int fd = open("/tmp/testfile.txt", O_RDONLY);
    if (fd == -1) {
        perror("open");
        return;
    }
    int newfd = dup2(fd, 10);
    if (newfd == -1) {
        perror("dup2");
    } else {
        printf("File descriptor duplicated successfully\n");
        close(newfd);
    }
    close(fd);
}

// pause
void template_pause() {
    printf("Pausing until a signal is received...\n");
    pause();
    printf("Signal received, resuming execution\n");
}



// nanosleep
void template_nanosleep() {
    struct timespec req = {1, 0}; // Sleep for 1 second
    if (nanosleep(&req, NULL) == -1) {
        perror("nanosleep");
    } else {
        printf("Slept for 1 second\n");
    }
}

// getitimer
void template_getitimer() {
    struct itimerval value;
    if (getitimer(ITIMER_REAL, &value) == -1) {
        perror("getitimer");
    } else {
        printf("Interval timer retrieved successfully\n");
    }
}


// alarm
void template_alarm() {
    unsigned int seconds = 5;
    unsigned int remaining = alarm(seconds);
    printf("Alarm set for %u seconds, previously set alarm had %u seconds remaining\n", seconds, remaining);
}

// setitimer
void template_setitimer() {
    struct itimerval value;
    value.it_value.tv_sec = 5;
    value.it_value.tv_usec = 0;
    value.it_interval.tv_sec = 0;
    value.it_interval.tv_usec = 0;
    if (setitimer(ITIMER_REAL, &value, NULL) == -1) {
        perror("setitimer");
    } else {
        printf("Interval timer set successfully\n");
    }
}

// getpid
void template_getpid() {
    pid_t pid = getpid();
    printf("Current process ID: %d\n", pid);
}


// sendfile64
void template_sendfile64() {
    int in_fd = open("/tmp/testfile.txt", O_RDONLY);
    if (in_fd == -1) {
        perror("open");
        return;
    }
    int out_fd = open("/tmp/testfile_copy.txt", O_WRONLY | O_CREAT, 0644);
    if (out_fd == -1) {
        perror("open");
        close(in_fd);
        return;
    }
    off_t offset = 0;
    ssize_t bytesSent = sendfile(out_fd, in_fd, &offset, 4096);
    if (bytesSent == -1) {
        perror("sendfile");
    } else {
        printf("Sent %zd bytes\n", bytesSent);
    }
    close(in_fd);
    close(out_fd);
}

// socket
void template_socket() {
    int sockfd = socket(AF_INET, SOCK_STREAM, 0);
    if (sockfd == -1) {
        perror("socket");
    } else {
        printf("Socket created successfully\n");
        close(sockfd);
    }
}

// connect
void template_connect() {
    int sockfd = socket(AF_INET, SOCK_STREAM, 0);
    if (sockfd == -1) {
        perror("socket");
        return;
    }
    struct sockaddr_in addr;
    addr.sin_family = AF_INET;
    addr.sin_port = htons(80);
    addr.sin_addr.s_addr = inet_addr("93.184.216.34"); // example.com
    if (connect(sockfd, (struct sockaddr *)&addr, sizeof(addr)) == -1) {
        perror("connect");
    } else {
        printf("Connected successfully\n");
    }
    close(sockfd);
}


// accept
void template_accept() {
    int sockfd = socket(AF_INET, SOCK_STREAM, 0);
    if (sockfd == -1) {
        perror("socket");
        return;
    }
    struct sockaddr_in addr;
    addr.sin_family = AF_INET;
    addr.sin_port = htons(8080);
    addr.sin_addr.s_addr = INADDR_ANY;
    if (bind(sockfd, (struct sockaddr *)&addr, sizeof(addr)) == -1) {
        perror("bind");
        close(sockfd);
        return;
    }
    if (listen(sockfd, 5) == -1) {
        perror("listen");
        close(sockfd);
        return;
    }
    struct sockaddr_in client_addr;
    socklen_t client_len = sizeof(client_addr);
    int client_fd = accept(sockfd, (struct sockaddr *)&client_addr, &client_len);
    if (client_fd == -1) {
        perror("accept");
    } else {
        printf("Accepted connection\n");
        close(client_fd);
    }
    close(sockfd);
}

// sendto
void template_sendto() {
    int sockfd = socket(AF_INET, SOCK_DGRAM, 0);
    if (sockfd == -1) {
        perror("socket");
        return;
    }
    struct sockaddr_in addr;
    addr.sin_family = AF_INET;
    addr.sin_port = htons(8080);
    addr.sin_addr.s_addr = inet_addr("127.0.0.1");
    const char *message = "Hello, World!";
    if (sendto(sockfd, message, strlen(message), 0, (struct sockaddr *)&addr, sizeof(addr)) == -1) {
        perror("sendto");
    } else {
        printf("Message sent successfully\n");
    }
    close(sockfd);
}


// recvfrom
void template_recvfrom() {
    int sockfd = socket(AF_INET, SOCK_DGRAM, 0);
    if (sockfd == -1) {
        perror("socket");
        return;
    }
    struct sockaddr_in addr;
    addr.sin_family = AF_INET;
    addr.sin_port = htons(8080);
    addr.sin_addr.s_addr = INADDR_ANY;
    if (bind(sockfd, (struct sockaddr *)&addr, sizeof(addr)) == -1) {
        perror("bind");
        close(sockfd);
        return;
    }
    char buffer[100];
    struct sockaddr_in sender_addr;
    socklen_t sender_len = sizeof(sender_addr);
    ssize_t bytesReceived = recvfrom(sockfd, buffer, sizeof(buffer) - 1, 0, (struct sockaddr *)&sender_addr, &sender_len);
    if (bytesReceived == -1) {
        perror("recvfrom");
    } else {
        buffer[bytesReceived] = '\0';
        printf("Received %zd bytes: %s\n", bytesReceived, buffer);
    }
    close(sockfd);
}

// sendmsg
void template_sendmsg() {
    int sockfd = socket(AF_INET, SOCK_DGRAM, 0);
    if (sockfd == -1) {
        perror("socket");
        return;
    }
    struct sockaddr_in addr;
    addr.sin_family = AF_INET;
    addr.sin_port = htons(8080);
    addr.sin_addr.s_addr = inet_addr("127.0.0.1");
    struct msghdr msg;
    struct iovec iov[1];
    const char *message = "Hello, World!";
    iov[0].iov_base = (void *)message;
    iov[0].iov_len = strlen(message);
    msg.msg_name = &addr;
    msg.msg_namelen = sizeof(addr);
    msg.msg_iov = iov;
    msg.msg_iovlen = 1;
    msg.msg_control = NULL;
    msg.msg_controllen = 0;
    msg.msg_flags = 0;
    if (sendmsg(sockfd, &msg, 0) == -1) {
        perror("sendmsg");
    } else {
        printf("Message sent successfully\n");
    }
    close(sockfd);
}


// recvmsg
void template_recvmsg() {
    int sockfd = socket(AF_INET, SOCK_DGRAM, 0);
    if (sockfd == -1) {
        perror("socket");
        return;
    }
    struct sockaddr_in addr;
    addr.sin_family = AF_INET;
    addr.sin_port = htons(8080);
    addr.sin_addr.s_addr = INADDR_ANY;
    if (bind(sockfd, (struct sockaddr *)&addr, sizeof(addr)) == -1) {
        perror("bind");
        close(sockfd);
        return;
    }
    struct msghdr msg;
    struct iovec iov[1];
    char buffer[100];
    iov[0].iov_base = buffer;
    iov[0].iov_len = sizeof(buffer) - 1;
    msg.msg_name = &addr;
    msg.msg_namelen = sizeof(addr);
    msg.msg_iov = iov;
    msg.msg_iovlen = 1;
    msg.msg_control = NULL;
    msg.msg_controllen = 0;
    msg.msg_flags = 0;
    ssize_t bytesReceived = recvmsg(sockfd, &msg, 0);
    if (bytesReceived == -1) {
        perror("recvmsg");
    } else {
        buffer[bytesReceived] = '\0';
        printf("Received %zd bytes: %s\n", bytesReceived, buffer);
    }
    close(sockfd);
}

// shutdown
void template_shutdown() {
    int sockfd = socket(AF_INET, SOCK_STREAM, 0);
    if (sockfd == -1) {
        perror("socket");
        return;
    }
    if (shutdown(sockfd, SHUT_RDWR) == -1) {
        perror("shutdown");
    } else {
        printf("Socket shutdown successfully\n");
    }
    close(sockfd);
}

// bind
void template_bind() {
    int sockfd = socket(AF_INET, SOCK_STREAM, 0);
    if (sockfd == -1) {
        perror("socket");
        return;
    }
    struct sockaddr_in addr;
    addr.sin_family = AF_INET;
    addr.sin_port = htons(8080);
    addr.sin_addr.s_addr = INADDR_ANY;
    if (bind(sockfd, (struct sockaddr *)&addr, sizeof(addr)) == -1) {
        perror("bind");
    } else {
        printf("Socket bound successfully\n");
    }
    close(sockfd);
}

// listen
void template_listen() {
    int sockfd = socket(AF_INET, SOCK_STREAM, 0);
    if (sockfd == -1) {
        perror("socket");
        return;
    }
    struct sockaddr_in addr;
    addr.sin_family = AF_INET;
    addr.sin_port = htons(8080);
    addr.sin_addr.s_addr = INADDR_ANY;
    if (bind(sockfd, (struct sockaddr *)&addr, sizeof(addr)) == -1) {
        perror("bind");
        close(sockfd);
        return;
    }
    if (listen(sockfd, 5) == -1) {
        perror("listen");
    } else {
        printf("Socket is listening\n");
    }
    close(sockfd);
}


// getsockname
void template_getsockname() {
    int sockfd = socket(AF_INET, SOCK_STREAM, 0);
    if (sockfd == -1) {
        perror("socket");
        return;
    }
    struct sockaddr_in addr;
    addr.sin_family = AF_INET;
    addr.sin_port = htons(8080);
    addr.sin_addr.s_addr = INADDR_ANY;
    if (bind(sockfd, (struct sockaddr *)&addr, sizeof(addr)) == -1) {
        perror("bind");
        close(sockfd);
        return;
    }
    struct sockaddr_in name;
    socklen_t namelen = sizeof(name);
    if (getsockname(sockfd, (struct sockaddr *)&name, &namelen) == -1) {
        perror("getsockname");
    } else {
        printf("Socket name: %s:%d\n", inet_ntoa(name.sin_addr), ntohs(name.sin_port));
    }
    close(sockfd);
}

// getpeername
void template_getpeername() {
    int sockfd = socket(AF_INET, SOCK_STREAM, 0);
    if (sockfd == -1) {
        perror("socket");
        return;
    }
    struct sockaddr_in addr;
    addr.sin_family = AF_INET;
    addr.sin_port = htons(80);
    addr.sin_addr.s_addr = inet_addr("93.184.216.34"); // example.com
    if (connect(sockfd, (struct sockaddr *)&addr, sizeof(addr)) == -1) {
        perror("connect");
        close(sockfd);
        return;
    }
    struct sockaddr_in peer;
    socklen_t peerlen = sizeof(peer);
    if (getpeername(sockfd, (struct sockaddr *)&peer, &peerlen) == -1) {
        perror("getpeername");
    } else {
        printf("Peer name: %s:%d\n", inet_ntoa(peer.sin_addr), ntohs(peer.sin_port));
    }
    close(sockfd);
}

// socketpair
void template_socketpair() {
    int sv[2];
    if (socketpair(AF_UNIX, SOCK_STREAM, 0, sv) == -1) {
        perror("socketpair");
    } else {
        printf("Socket pair created successfully\n");
        close(sv[0]);
        close(sv[1]);
    }
}

// setsockopt
void template_setsockopt() {
    int sockfd = socket(AF_INET, SOCK_STREAM, 0);
    if (sockfd == -1) {
        perror("socket");
        return;
    }
    int optval = 1;
    if (setsockopt(sockfd, SOL_SOCKET, SO_REUSEADDR, &optval, sizeof(optval)) == -1) {
        perror("setsockopt");
    } else {
        printf("Socket option set successfully\n");
    }
    close(sockfd);
}

// getsockopt
void template_getsockopt() {
    int sockfd = socket(AF_INET, SOCK_STREAM, 0);
    if (sockfd == -1) {
        perror("socket");
        return;
    }
    int optval;
    socklen_t optlen = sizeof(optval);
    if (getsockopt(sockfd, SOL_SOCKET, SO_REUSEADDR, &optval, &optlen) == -1) {
        perror("getsockopt");
    } else {
        printf("Socket option value: %d\n", optval);
    }
    close(sockfd);
}


void template_clone() {
    char *stack;                    // Start of stack buffer
    char *stack_top;                // End of stack buffer
    pid_t pid;

    // Allocate stack for the new thread
    stack = malloc(STACK_SIZE);
    if (stack == NULL) {
        perror("malloc");
        exit(EXIT_FAILURE);
    }
    stack_top = stack + STACK_SIZE; // Assume stack grows downward

    // Create a new thread using clone
    pid = clone(thread_function, stack_top, CLONE_VM | CLONE_FS | CLONE_FILES | CLONE_SIGHAND | CLONE_THREAD, NULL);
    if (pid == -1) {
        perror("clone");
        free(stack);
        exit(EXIT_FAILURE);
    }

    // In the parent, the clone system call returns the PID of the child thread
    // In the child, it returns 0
    if (pid == 0) {
        // This block will be executed by the new thread
        printf("Child thread: PID = %d\n", getpid());
    } else {
        // This block will be executed by the parent
        printf("Parent function: PID = %d, Child PID = %d\n", getpid(), pid);
        // Wait for the child thread to finish (not ideal for clone-based threads)
        // Usually, clone will require manual synchronization or signaling
        // (e.g., using mutexes, condition variables, or other mechanisms).
    }

    // Free the allocated stack
    free(stack);
}


// fork
void template_fork() {
    pid_t pid = fork();
    if (pid == -1) {
        perror("fork");
    } else if (pid == 0) {
        printf("Child process\n");
        exit(0);
    } else {
        printf("Parent process, child PID: %d\n", pid);
        wait(NULL);
    }
}

// vfork
void template_vfork() {
    pid_t pid = vfork();
    if (pid == -1) {
        perror("vfork");
    } else if (pid == 0) {
        printf("Child process\n");
        _exit(0);
    } else {
        printf("Parent process, child PID: %d\n", pid);
    }
}

// execve
void template_execve() {
    char *argv[] = {"/bin/ls", NULL};
    char *envp[] = {NULL};
    if (execve("/bin/ls", argv, envp) == -1) {
        perror("execve");
    }
}

// exit
void template_exit() {
    printf("Exiting process\n");
    _exit(0);
}

// wait4
void template_wait4() {
    pid_t pid = fork();
    if (pid == -1) {
        perror("fork");
    } else if (pid == 0) {
        printf("Child process\n");
        exit(0);
    } else {
        struct rusage usage;
        if (wait4(pid, NULL, 0, &usage) == -1) {
            perror("wait4");
        } else {
            printf("Child process terminated\n");
        }
    }
}

// kill
void template_kill() {
    pid_t pid = getpid();
    if (kill(pid, SIGUSR1) == -1) {
        perror("kill");
    } else {
        printf("Signal sent successfully\n");
    }
}


// newuname
void template_newuname() {
    struct utsname buf;
    if (uname(&buf) == -1) {
        perror("uname");
    } else {
        printf("System name: %s\n", buf.sysname);
    }
}

// semget
void template_semget() {
    int semid = semget(IPC_PRIVATE, 1, IPC_CREAT | 0666);
    if (semid == -1) {
        perror("semget");
    } else {
        printf("Semaphore set created successfully\n");
    }
}

// semop
void template_semop() {
    int semid = semget(IPC_PRIVATE, 1, IPC_CREAT | 0666);
    if (semid == -1) {
        perror("semget");
        return;
    }
    struct sembuf sops[1];
    sops[0].sem_num = 0;
    sops[0].sem_op = -1;
    sops[0].sem_flg = 0;
    if (semop(semid, sops, 1) == -1) {
        perror("semop");
    } else {
        printf("Semaphore operation executed successfully\n");
    }
}

// semctl
void template_semctl() {
    int semid = semget(IPC_PRIVATE, 1, IPC_CREAT | 0666);
    if (semid == -1) {
        perror("semget");
        return;
    }
    if (semctl(semid, 0, IPC_RMID) == -1) {
        perror("semctl");
    } else {
        printf("Semaphore control operation executed successfully\n");
    }
}

// shmdt
void template_shmdt() {
    int shmid = shmget(IPC_PRIVATE, 4096, IPC_CREAT | 0666);
    if (shmid == -1) {
        perror("shmget");
        return;
    }
    void *shmaddr = shmat(shmid, NULL, 0);
    if (shmaddr == (void *)-1) {
        perror("shmat");
        return;
    }
    if (shmdt(shmaddr) == -1) {
        perror("shmdt");
    } else {
        printf("Shared memory detached successfully\n");
    }
}

// msgget
void template_msgget() {
    int msgid = msgget(IPC_PRIVATE, IPC_CREAT | 0666);
    if (msgid == -1) {
        perror("msgget");
    } else {
        printf("Message queue created successfully\n");
    }
}

// msgsnd
void template_msgsnd() {
    int msgid = msgget(IPC_PRIVATE, IPC_CREAT | 0666);
    if (msgid == -1) {
        perror("msgget");
        return;
    }
    struct msgbuf {
        long mtype;
        char mtext[100];
    } msg;
    msg.mtype = 1;
    strcpy(msg.mtext, "Hello, World!");
    if (msgsnd(msgid, &msg, sizeof(msg.mtext), 0) == -1) {
        perror("msgsnd");
    } else {
        printf("Message sent successfully\n");
    }
}


// msgrcv
void template_msgrcv() {
    int msgid = msgget(IPC_PRIVATE, IPC_CREAT | 0666);
    if (msgid == -1) {
        perror("msgget");
        return;
    }
    struct msgbuf {
        long mtype;
        char mtext[100];
    } msg;
    if (msgrcv(msgid, &msg, sizeof(msg.mtext), 0, 0) == -1) {
        perror("msgrcv");
    } else {
        printf("Received message: %s\n", msg.mtext);
    }
}

// msgctl
void template_msgctl() {
    int msgid = msgget(IPC_PRIVATE, IPC_CREAT | 0666);
    if (msgid == -1) {
        perror("msgget");
        return;
    }
    if (msgctl(msgid, IPC_RMID, NULL) == -1) {
        perror("msgctl");
    } else {
        printf("Message queue control operation executed successfully\n");
    }
}

// fcntl
void template_fcntl() {
    int fd = open("/tmp/testfile.txt", O_RDONLY);
    if (fd == -1) {
        perror("open");
        return;
    }
    int flags = fcntl(fd, F_GETFL);
    if (flags == -1) {
        perror("fcntl");
    } else {
        printf("File status flags: %d\n", flags);
    }
    close(fd);
}

// flock
void template_flock() {
    int fd = open("/home/zephyros/Desktop/attackGAN-IDS/pythonScript/cScripts/testfil.txt", O_RDONLY);
    if (fd == -1) {
        perror("open");
        return;
    }
    if (flock(fd, LOCK_EX) == -1) {
        perror("flock");
    } else {
        printf("File locked successfully\n");
        flock(fd, LOCK_UN);
    }
    close(fd);
}

// fsync
void template_fsync() {
    int fd = open("/tmp/testfile.txt", O_WRONLY);
    if (fd == -1) {
        perror("open");
        return;
    }
    if (fsync(fd) == -1) {
        perror("fsync");
    } else {
        printf("File synchronized successfully\n");
    }
    close(fd);
}

// fdatasync
void template_fdatasync() {
    int fd = open("/tmp/testfile.txt", O_WRONLY);
    if (fd == -1) {
        perror("open");
        return;
    }
    if (fdatasync(fd) == -1) {
        perror("fdatasync");
    } else {
        printf("File data synchronized successfully\n");
    }
    close(fd);
}

// truncate
void template_truncate() {
    if (truncate("/tmp/testfile.txt", 100) == -1) {
        perror("truncate");
    } else {
        printf("File truncated successfully\n");
    }
}

// ftruncate
void template_ftruncate() {
    int fd = open("/tmp/testfile.txt", O_WRONLY);
    if (fd == -1) {
        perror("open");
        return;
    }
    if (ftruncate(fd, 100) == -1) {
        perror("ftruncate");
    } else {
        printf("File truncated successfully\n");
    }
    close(fd);
}

// getdents
void template_getdents() {
    int fd = open("/tmp", O_RDONLY | O_DIRECTORY);
    if (fd == -1) {
        perror("open");
        return;
    }
    char buffer[1024];
    int nread = syscall(SYS_getdents64, fd, buffer, sizeof(buffer));
    if (nread == -1) {
        perror("getdents");
    } else {
        printf("Read %d bytes from directory\n", nread);
    }
    close(fd);
}

// getcwd
void template_getcwd() {
    char buffer[1024];
    if (getcwd(buffer, sizeof(buffer)) == NULL) {
        perror("getcwd");
    } else {
        printf("Current working directory: %s\n", buffer);
    }
}

// chdir
void template_chdir() {
    if (chdir("/tmp") == -1) {
        perror("chdir");
    } else {
        printf("Changed directory to /tmp\n");
    }
}


// fchdir
void template_fchdir() {
    int fd = open("/tmp", O_RDONLY);
    if (fd == -1) {
        perror("open");
        return;
    }
    if (fchdir(fd) == -1) {
        perror("fchdir");
    } else {
        printf("Changed directory using file descriptor\n");
    }
    close(fd);
}

// rename
void template_rename() {
    if (rename("/tmp/testfile.txt", "/tmp/testfile_renamed.txt") == -1) {
        perror("rename");
    } else {
        printf("File renamed successfully\n");
    }
}

// mkdir
void template_mkdir() {
    if (mkdir("/tmp/testdir", 0755) == -1) {
        perror("mkdir");
    } else {
        printf("Directory created successfully\n");
    }
}

// rmdir
void template_rmdir() {
    if (rmdir("/tmp/testdir") == -1) {
        perror("rmdir");
    } else {
        printf("Directory removed successfully\n");
    }
}

// creat
void template_creat() {
    int fd = creat("/tmp/testfile.txt", 0644);
    if (fd == -1) {
        perror("creat");
    } else {
        printf("File created successfully\n");
        close(fd);
    }
}

// link
void template_link() {
    if (link("/tmp/testfile.txt", "/tmp/testfile_link.txt") == -1) {
        perror("link");
    } else {
        printf("Hard link created successfully\n");
    }
}

// unlink
void template_unlink() {
    if (unlink("/tmp/testfile_link.txt") == -1) {
        perror("unlink");
    } else {
        printf("File unlinked successfully\n");
    }
}

// symlink
void template_symlink() {
    if (symlink("/tmp/testfile.txt", "/tmp/testfile_symlink.txt") == -1) {
        perror("symlink");
    } else {
        printf("Symbolic link created successfully\n");
    }
}

// readlink
void template_readlink() {
    char buffer[1024];
    ssize_t len = readlink("/tmp/testfile_symlink.txt", buffer, sizeof(buffer) - 1);
    if (len == -1) {
        perror("readlink");
    } else {
        buffer[len] = '\0';
        printf("Symbolic link points to: %s\n", buffer);
    }
}

// chmod
void template_chmod() {
    if (chmod("/tmp/testfile.txt", 0644) == -1) {
        perror("chmod");
    } else {
        printf("File permissions changed successfully\n");
    }
}

// fchmod
void template_fchmod() {
    int fd = open("/tmp/testfile.txt", O_RDONLY);
    if (fd == -1) {
        perror("open");
        return;
    }
    if (fchmod(fd, 0644) == -1) {
        perror("fchmod");
    } else {
        printf("File permissions changed successfully\n");
    }
    close(fd);
}

// chown
void template_chown() {
    if (chown("/tmp/testfile.txt", 1000, 1000) == -1) {
        perror("chown");
    } else {
        printf("File ownership changed successfully\n");
    }
}

// fchown
void template_fchown() {
    int fd = open("/tmp/testfile.txt", O_RDONLY);
    if (fd == -1) {
        perror("open");
        return;
    }
    if (fchown(fd, 1000, 1000) == -1) {
        perror("fchown");
    } else {
        printf("File ownership changed successfully\n");
    }
    close(fd);
}

// lchown
void template_lchown() {
    if (lchown("/tmp/testfile_symlink.txt", 1000, 1000) == -1) {
        perror("lchown");
    } else {
        printf("Symbolic link ownership changed successfully\n");
    }
}

// umask
void template_umask() {
    mode_t old_mask = umask(022);
    printf("Old umask: %04o\n", old_mask);
}

// gettimeofday
void template_gettimeofday() {
    struct timeval tv;
    if (gettimeofday(&tv, NULL) == -1) {
        perror("gettimeofday");
    } else {
        printf("Seconds: %ld, Microseconds: %ld\n", tv.tv_sec, tv.tv_usec);
    }
}

// getrlimit
void template_getrlimit() {
    struct rlimit rl;
    if (getrlimit(RLIMIT_NOFILE, &rl) == 0) {
        printf("RLIMIT_NOFILE: soft limit = %ld, hard limit = %ld\n", rl.rlim_cur, rl.rlim_max);
    } else {
        perror("getrlimit");
    }
}

// getrusage
void template_getrusage() {
    struct rusage usage;
    if (getrusage(RUSAGE_SELF, &usage) == 0) {
        printf("User CPU time used: %ld.%06ld sec\n", usage.ru_utime.tv_sec, usage.ru_utime.tv_usec);
        printf("System CPU time used: %ld.%06ld sec\n", usage.ru_stime.tv_sec, usage.ru_stime.tv_usec);
    } else {
        perror("getrusage");
    }
}

// sysinfo
void template_sysinfo() {
    struct sysinfo info;
    if (sysinfo(&info) == 0) {
        printf("Uptime: %ld seconds\n", info.uptime);
        printf("Total RAM: %lu bytes\n", info.totalram);
        printf("Free RAM: %lu bytes\n", info.freeram);
    } else {
        perror("sysinfo");
    }
}

// times
void template_times() {
    struct tms t;
    clock_t time = times(&t);
    if (time == (clock_t)-1) {
        perror("times");
    } else {
        printf("User CPU time: %ld, System CPU time: %ld\n", t.tms_utime, t.tms_stime);
    }
}
void template_splice() {
    int pipes[2];
    pipe(pipes);
    splice(pipes[0], NULL, pipes[1], NULL, 4096, SPLICE_F_MOVE);
    close(pipes[0]);
    close(pipes[1]);
}
//----------------------100 finished ---- ----



//starting from 151 ------------



void template_mlockall() {
    if (mlockall(MCL_CURRENT | MCL_FUTURE) == -1) {
        perror("mlockall");
    } else {
        printf("All memory locked successfully.\n");
    }
}

// munlockall
void template_munlockall() {
    if (munlockall() == -1) {
        perror("munlockall");
    } else {
        printf("All memory unlocked successfully.\n");
    }
}

// vhangup
void template_vhangup() {
    if (vhangup() == -1) {
        perror("vhangup");
    } else {
        printf("Virtual hangup performed successfully.\n");
    }
}

void template_modify_ldt() {
    struct user_desc ldt_entry;
    memset(&ldt_entry, 0, sizeof(ldt_entry));

    ldt_entry.entry_number = 0;     // Segment entry number
    ldt_entry.base_addr = 0;        // Starting address for the segment
    ldt_entry.limit = 0xFFFFF;      // Segment limit
    ldt_entry.seg_32bit = 1;        // 32-bit segment
    ldt_entry.contents = 0;         // Data segment
    ldt_entry.read_exec_only = 0;   // Read/write segment
    ldt_entry.limit_in_pages = 1;   // Segment limit is in pages (4 KB)
    ldt_entry.seg_not_present = 0;  // Segment is present
    ldt_entry.useable = 1;          // Segment is usable

    // Call modify_ldt syscall with LDT write flag (1) and check for errors
    int result = syscall(SYS_modify_ldt, 1, &ldt_entry, sizeof(ldt_entry));
    if (result == -1) {
        perror("modify_ldt");
    } else {
        printf("LDT entry modified successfully\n");
    }
}
// pivot_root
void template_pivot_root() {
    const char *new_root = "/new_root";
    const char *put_old = "/new_root/old_root";

    // Ensure the new root and old root directories exist
    if (mkdir(new_root, 0755) == -1 && errno != EEXIST) {
        perror("mkdir new_root");
        return;
    }
    if (mkdir(put_old, 0755) == -1 && errno != EEXIST) {
        perror("mkdir put_old");
        return;
    }

    // Mount the new root filesystem
    if (mount("none", new_root, "tmpfs", 0, "") == -1) {
        perror("mount new_root");
        return;
    }

    // Perform the pivot_root system call
    if (syscall(SYS_pivot_root, new_root, put_old) == -1) {
        perror("pivot_root");
        return;
    }

    // Change the current working directory to the new root
    if (chdir("/") == -1) {
        perror("chdir");
        return;
    }

    // Unmount the old root
    if (umount2("/old_root", MNT_DETACH) == -1) {
        perror("umount2");
        return;
    }

    // Remove the old root directory
    if (rmdir("/old_root") == -1) {
        perror("rmdir");
        return;
    }

    printf("pivot_root executed successfully\n");
}


// prctl
void template_prctl() {
    if (prctl(PR_SET_NAME, "newname", 0, 0, 0) == -1) {
        perror("prctl");
    } else {
        printf("Process name set successfully.\n");
    }
}

void template_arch_prctl() {
    unsigned long fs_base;
    unsigned long new_fs_base = 0x12345678;

    // Set the FS base address
    if (syscall(SYS_arch_prctl, ARCH_SET_FS, new_fs_base) == -1) {
        perror("arch_prctl ARCH_SET_FS");
        return;
    }
    printf("FS base address set to: 0x%lx\n", new_fs_base);

    // Get the FS base address
    if (syscall(SYS_arch_prctl, ARCH_GET_FS, &fs_base) == -1) {
        perror("arch_prctl ARCH_GET_FS");
        return;
    }
    printf("FS base address: 0x%lx\n", fs_base);
}


void template_adjtimex() {
    struct timex tx;
    int result;

    // Initialize the timex structure
    tx.modes = 0;

    // Call adjtimex to query the current time status
    result = syscall(SYS_adjtimex, &tx);
    if (result == -1) {
        perror("adjtimex");
        return;
    }

    // Print the current time status
    printf("adjtimex returned: %d\n", result);
    printf("Time offset: %ld\n", tx.offset);
    printf("Frequency: %ld\n", tx.freq);
    printf("Max error: %ld\n", tx.maxerror);
    printf("Est error: %ld\n", tx.esterror);
    printf("Status: %d\n", tx.status);
    printf("Constant: %ld\n", tx.constant);
    printf("Precision: %ld\n", tx.precision);
    printf("Tolerance: %ld\n", tx.tolerance);
    printf("Tick: %ld\n", tx.tick);
    printf("PPM: %ld\n", tx.ppsfreq);
    printf("Jitter: %ld\n", tx.jitter);
    printf("Stabil: %ld\n", tx.stabil);
    printf("Jitcnt: %ld\n", tx.jitcnt);
    printf("Calcnt: %ld\n", tx.calcnt);
    printf("Errcnt: %ld\n", tx.errcnt);
    printf("Stbcnt: %ld\n", tx.stbcnt);
}



// setrlimit
void template_setrlimit() {
    struct rlimit rl;
    rl.rlim_cur = 1024;
    rl.rlim_max = 2048;
    if (setrlimit(RLIMIT_NOFILE, &rl) == -1) {
        perror("setrlimit");
    } else {
        printf("Resource limits set successfully.\n");
    }
}

// chroot
void template_chroot() {
    if (chroot("/tmp") == -1) {
        perror("chroot");
    } else {
        printf("Changed root directory successfully.\n");
    }
}

// sync
void template_sync() {
    sync();
    printf("Filesystem buffers synchronized.\n");
}

// acct
void template_acct() {
    if (acct("/tmp/acctfile") == -1) {
        perror("acct");
    } else {
        printf("Process accounting enabled.\n");
    }
}

// settimeofday
void template_settimeofday() {
    struct timeval tv;
    tv.tv_sec = time(NULL);
    tv.tv_usec = 0;
    if (settimeofday(&tv, NULL) == -1) {
        perror("settimeofday");
    } else {
        printf("System time set successfully.\n");
    }
}

// mount
void template_mount() {
    if (mount("none", "/mnt", "tmpfs", 0, "") == -1) {
        perror("mount");
    } else {
        printf("Filesystem mounted successfully.\n");
    }
}

// umount
void template_umount() {
    if (umount("/mnt") == -1) {
        perror("umount");
    } else {
        printf("Filesystem unmounted successfully.\n");
    }
}

// swapon
void template_swapon() {
    if (swapon("/swapfile", 0) == -1) {
        perror("swapon");
    } else {
        printf("Swap space enabled.\n");
    }
}

// swapoff
void template_swapoff() {
    if (swapoff("/swapfile") == -1) {
        perror("swapoff");
    } else {
        printf("Swap space disabled.\n");
    }
}

// reboot
void template_reboot() {
    if (reboot(RB_AUTOBOOT) == -1) {
        perror("reboot");
    } else {
        printf("System reboot initiated.\n");
    }
}

// sethostname
void template_sethostname() {
    if (sethostname("newhostname", strlen("newhostname")) == -1) {
        perror("sethostname");
    } else {
        printf("Hostname set successfully.\n");
    }
}

// setdomainname
void template_setdomainname() {
    if (setdomainname("example.com", strlen("example.com")) == -1) {
        perror("setdomainname");
    } else {
        printf("Domain name set successfully.\n");
    }
}

// iopl

void template_iopl() {
    if (syscall(SYS_iopl, 3) == -1) {
        perror("iopl");
    } else {
        printf("I/O privilege level set successfully\n");
    }
}

// ioperm

// ioperm
void template_ioperm() {
    if (syscall(SYS_ioperm, 0x378, 3, 1) == -1) {
        perror("ioperm");
    } else {
        printf("I/O permissions set successfully\n");
    }
}


// init_module
void template_init_module() {
    const char *module_path = "/path/to/module.ko";
    int fd;
    struct stat st;
    void *module_image;
    const char *params = "";

    // Open the module file
    fd = open(module_path, O_RDONLY);
    if (fd == -1) {
        perror("open");
        return;
    }

    // Get the size of the module file
    if (fstat(fd, &st) == -1) {
        perror("fstat");
        close(fd);
        return;
    }

    // Map the module file into memory
    module_image = mmap(NULL, st.st_size, PROT_READ, MAP_PRIVATE, fd, 0);
    if (module_image == MAP_FAILED) {
        perror("mmap");
        close(fd);
        return;
    }

    // Load the module using init_module
    if (syscall(SYS_init_module, module_image, st.st_size, params) == -1) {
        perror("init_module");
    } else {
        printf("Module loaded successfully\n");
    }

    // Clean up
    munmap(module_image, st.st_size);
    close(fd);
}


void template_delete_module() {
    const char *module_name = "module_name";  // Replace with the actual module name
    int flags = O_NONBLOCK | O_EXCL;  // Flags for delete_module

    // Unload the module using delete_module
    if (syscall(SYS_delete_module, module_name, flags) == -1) {
        perror("delete_module");
    } else {
        printf("Module unloaded successfully\n");
    }
}



// quotactl
void template_quotactl() {
    const char *filesystem = "/";  // Filesystem to query
    int cmd = Q_GETQUOTA;          // Command to get quota information
    int type = USRQUOTA;           // Type of quota (user quota)
    int id = getuid();             // User ID to query
    struct dqblk dq;               // Structure to hold quota information

    // Initialize the dqblk structure
    memset(&dq, 0, sizeof(dq));

    // Call quotactl to get quota information
    if (quotactl(QCMD(cmd, type), filesystem, id, (caddr_t)&dq) == -1) {
        perror("quotactl");
        return;
    }

    // Print quota information
    printf("Disk quota information for user ID %d:\n", id);
    printf("  Block hard limit: %llu\n", (unsigned long long)dq.dqb_bhardlimit);
    printf("  Block soft limit: %llu\n", (unsigned long long)dq.dqb_bsoftlimit);
    printf("  Current block usage: %llu\n", (unsigned long long)dq.dqb_curspace);
    printf("  Inode hard limit: %llu\n", (unsigned long long)dq.dqb_ihardlimit);
    printf("  Inode soft limit: %llu\n", (unsigned long long)dq.dqb_isoftlimit);
    printf("  Current inode usage: %llu\n", (unsigned long long)dq.dqb_curinodes);
}




// gettid
void template_gettid() {
    pid_t tid = syscall(SYS_gettid);
    printf("Thread ID: %d\n", tid);
}

// readahead
void template_readahead() {
    int fd = open("/tmp/testfile.txt", O_RDONLY);
    if (fd == -1) {
        perror("open");
        return;
    }
    if (readahead(fd, 0, 4096) == -1) {
        perror("readahead");
    } else {
        printf("Readahead performed successfully.\n");
    }
    close(fd);
}

// setxattr
void template_setxattr() {
    if (setxattr("/tmp/testfile.txt", "user.test", "value", strlen("value"), 0) == -1) {
        perror("setxattr");
    } else {
        printf("Extended attribute set successfully.\n");
    }
}

// lsetxattr
void template_lsetxattr() {
    if (lsetxattr("/tmp/testfile_symlink.txt", "user.test", "value", strlen("value"), 0) == -1) {
        perror("lsetxattr");
    } else {
        printf("Extended attribute set successfully on symbolic link.\n");
    }
}

// fsetxattr
void template_fsetxattr() {
    int fd = open("/tmp/testfile.txt", O_WRONLY);
    if (fd == -1) {
        perror("open");
        return;
    }
    if (fsetxattr(fd, "user.test", "value", strlen("value"), 0) == -1) {
        perror("fsetxattr");
    } else {
        printf("Extended attribute set successfully using file descriptor.\n");
    }
    close(fd);
}

// getxattr
void template_getxattr() {
    char value[100];
    ssize_t ret = getxattr("/tmp/testfile.txt", "user.test", value, sizeof(value));
    if (ret == -1) {
        perror("getxattr");
    } else {
        printf("Extended attribute value: %s\n", value);
    }
}

// lgetxattr
void template_lgetxattr() {
    char value[100];
    ssize_t ret = lgetxattr("/tmp/testfile_symlink.txt", "user.test", value, sizeof(value));
    if (ret == -1) {
        perror("lgetxattr");
    } else {
        printf("Extended attribute value: %s\n", value);
    }
}

// fgetxattr
void template_fgetxattr() {
    int fd = open("/tmp/testfile.txt", O_RDONLY);
    if (fd == -1) {
        perror("open");
        return;
    }
    char value[100];
    ssize_t ret = fgetxattr(fd, "user.test", value, sizeof(value));
    if (ret == -1) {
        perror("fgetxattr");
    } else {
        printf("Extended attribute value: %s\n", value);
    }
    close(fd);
}

// listxattr
void template_listxattr() {
    char list[100];
    ssize_t ret = listxattr("/tmp/testfile.txt", list, sizeof(list));
    if (ret == -1) {
        perror("listxattr");
    } else {
        printf("Extended attribute list: %s\n", list);
    }
}

// llistxattr
void template_llistxattr() {
    char list[100];
    ssize_t ret = llistxattr("/tmp/testfile_symlink.txt", list, sizeof(list));
    if (ret == -1) {
        perror("llistxattr");
    } else {
        printf("Extended attribute list: %s\n", list);
    }
}

// flistxattr
void template_flistxattr() {
    int fd = open("/tmp/testfile.txt", O_RDONLY);
    if (fd == -1) {
        perror("open");
        return;
    }
    char list[100];
    ssize_t ret = flistxattr(fd, list, sizeof(list));
    if (ret == -1) {
        perror("flistxattr");
    } else {
        printf("Extended attribute list: %s\n", list);
    }
    close(fd);
}

// removexattr
void template_removexattr() {
    if (removexattr("/tmp/testfile.txt", "user.test") == -1) {
        perror("removexattr");
    } else {
        printf("Extended attribute removed successfully.\n");
    }
}

// lremovexattr
void template_lremovexattr() {
    if (lremovexattr("/tmp/testfile_symlink.txt", "user.test") == -1) {
        perror("lremovexattr");
    } else {
        printf("Extended attribute removed successfully from symbolic link.\n");
    }
}

// fremovexattr
void template_fremovexattr() {
    int fd = open("/tmp/testfile.txt", O_WRONLY);
    if (fd == -1) {
        perror("open");
        return;
    }
    if (fremovexattr(fd, "user.test") == -1) {
        perror("fremovexattr");
    } else {
        printf("Extended attribute removed successfully using file descriptor.\n");
    }
    close(fd);
}

// tkill
void template_tkill() {
    pid_t tid = syscall(SYS_gettid);  // Get the thread ID of the current thread
    if (syscall(SYS_tkill, tid, SIGUSR1) == -1) {
        perror("tkill");
    } else {
        printf("Signal sent successfully to thread %d\n", tid);
    }
}

// time
void template_time() {
    time_t t = time(NULL);
    if (t == (time_t)-1) {
        perror("time");
    } else {
        printf("Current time: %s", ctime(&t));
    }
}


// futex
void template_futex() {
    pthread_t threads[2];

    // Create two threads
    for (long i = 0; i < 2; i++) {
        if (pthread_create(&threads[i], NULL, thread_function_futex, (void *)i) != 0) {
            perror("pthread_create");
            exit(EXIT_FAILURE);
        }
    }

    // Wait for both threads to finish
    for (int i = 0; i < 2; i++) {
        pthread_join(threads[i], NULL);
    }
}



// sched_setaffinity
void template_sched_setaffinity() {
    cpu_set_t mask;
    CPU_ZERO(&mask);
    CPU_SET(0, &mask);
    if (sched_setaffinity(0, sizeof(mask), &mask) == -1) {
        perror("sched_setaffinity");
    } else {
        printf("CPU affinity set successfully.\n");
    }
}

// sched_getaffinity
void template_sched_getaffinity() {
    cpu_set_t mask;
    if (sched_getaffinity(0, sizeof(mask), &mask) == -1) {
        perror("sched_getaffinity");
    } else {
        printf("CPU affinity retrieved successfully.\n");
    }
}


// io_setup
void template_io_setup() {
    aio_context_t ctx = 0;
    unsigned nr_events = 10;  // Number of events
    int result;

    // Call io_setup to create an AIO context
    result = syscall(SYS_io_setup, nr_events, &ctx);
    if (result == -1) {
        perror("io_setup");
        return;
    }

    printf("AIO context created successfully\n");

    // Clean up the AIO context
    result = syscall(SYS_io_destroy, ctx);
    if (result == -1) {
        perror("io_destroy");
        return;
    }

    printf("AIO context destroyed successfully\n");
}



// io_destroy
void template_io_destroy() {
    aio_context_t ctx;
    int result;

    // Retrieve the context from the file
    FILE *file = fopen("/tmp/aio_context.txt", "r");
    if (file == NULL) {
        perror("fopen");
        return;
    }
    fscanf(file, "%llu", (unsigned long long *)&ctx);
    fclose(file);

    // Call io_destroy to destroy the AIO context
    result = syscall(SYS_io_destroy, ctx);
    if (result == -1) {
        perror("io_destroy");
        return;
    }

    printf("AIO context destroyed successfully\n");
}


// io_getevents
void template_io_getevents() {
    aio_context_t ctx;
    struct io_event events[10];
    struct timespec timeout;
    int result;

    // Retrieve the context from the file
    FILE *file = fopen("/tmp/aio_context.txt", "r");
    if (file == NULL) {
        perror("fopen");
        return;
    }
    fscanf(file, "%llu", (unsigned long long *)&ctx);
    fclose(file);

    // Set the timeout for io_getevents
    timeout.tv_sec = 1;  // 1 second
    timeout.tv_nsec = 0;

    // Call io_getevents to retrieve completed AIO events
    result = syscall(SYS_io_getevents, ctx, 1, 10, events, &timeout);
    if (result == -1) {
        perror("io_getevents");
        return;
    }

    printf("Retrieved %d AIO events\n", result);
    for (int i = 0; i < result; i++) {
        printf("Event %d: data=%p, obj=%p, res=%lld, res2=%lld\n",
               i, events[i].data, events[i].obj, (long long)events[i].res, (long long)events[i].res2);
    }
}



// till --------------208-------------------------


//starting from 301-------------------------------


void template_fanotify_mark() {
      int fd = fanotify_init(FAN_CLOEXEC | FAN_CLASS_NOTIF, O_RDONLY);
    if (fd == -1) {
        perror("fanotify_init failed");
        exit(EXIT_FAILURE);
    }

    if (fanotify_mark(fd, FAN_MARK_ADD, FAN_CREATE | FAN_DELETE, AT_FDCWD, "/tmp") == -1) {
        perror("fanotify_mark failed");
        close(fd);
        exit(EXIT_FAILURE);
    }

    printf("Fanotify initialized and marked.\n");

    close(fd);
}



#ifdef __NR_prlimit64
#include <sys/resource.h>
void template_prlimit64() {
    struct rlimit64 rl = {1024, 2048};
    prlimit64(getpid(), RLIMIT_NOFILE, &rl, NULL);

}
#endif


#ifdef __NR_name_to_handle_at
void template_name_to_handle_at() {
    struct file_handle handle;
    int mount_id;
    name_to_handle_at(AT_FDCWD, "/tmp/testfile.txt", &handle, &mount_id, 0);
}
#endif

#ifdef __NR_open_by_handle_at
void template_open_by_handle_at() {
    struct file_handle handle;
    int mount_id;
    int fd = open("/tmp/testfile.txt", O_RDONLY);
    if (fd != -1) {
        name_to_handle_at(AT_FDCWD, "/tmp/testfile.txt", &handle, &mount_id, 0);
        open_by_handle_at(fd, &handle, O_RDONLY);
        close(fd);
    }
}
#endif

#ifdef __NR_clock_adjtime
void template_clock_adjtime() {
    struct timex t = {0};
    clock_adjtime(CLOCK_REALTIME, &t);
}
#endif

#ifdef __NR_syncfs
void template_syncfs() {
    int fd = open("/", O_RDONLY);
    if (fd != -1) {
        syncfs(fd);
        close(fd);
    }
}
#endif

#ifdef __NR_sendmmsg
void template_sendmmsg() {
    int sockfd = socket(AF_INET, SOCK_DGRAM, 0);
    struct sockaddr_in addr = {0};
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);

    struct mmsghdr msgs[1];
    struct iovec iov[1];
    char buffer[] = "Hello";
    iov[0].iov_base = buffer;
    iov[0].iov_len = sizeof(buffer) - 1;
    msgs[0].msg_hdr.msg_iov = iov;
    msgs[0].msg_hdr.msg_iovlen = 1;

    sendmmsg(sockfd, msgs, 1, 0);
    close(sockfd);
}
#endif

#ifdef __NR_setns
void template_setns() {
    int fd = open("/proc/self/ns/mnt", O_RDONLY);
    if (fd != -1) {
        setns(fd, CLONE_NEWNS);
        close(fd);
    }
}
#endif

#ifdef __NR_getcpu
void template_getcpu() {
    unsigned cpu, node;
    getcpu(&cpu, &node);
}
#endif

#ifdef __NR_process_vm_readv
void template_process_vm_readv() {
    int pid = fork();
    if (pid == 0) {
        // Child process
        while (1);
    } else {
        // Parent process
        struct iovec local[1];
        struct iovec remote[1];
        char buffer[1024];
        local[0].iov_base = buffer;
        local[0].iov_len = sizeof(buffer);
        remote[0].iov_base = (void *)0x00400000;
        remote[0].iov_len = sizeof(buffer);
        process_vm_readv(pid, local, 1, remote, 1, 0);
        kill(pid, SIGKILL);
    }
}
#endif

#ifdef __NR_process_vm_writev
void template_process_vm_writev() {
    int pid = fork();
    if (pid == 0) {
        // Child process
        while (1);
    } else {
        // Parent process
        struct iovec local[1];
        struct iovec remote[1];
        char buffer[] = "Hello, world!";
        local[0].iov_base = buffer;
        local[0].iov_len = sizeof(buffer) - 1;
        remote[0].iov_base = (void *)0x00400000;
        remote[0].iov_len = sizeof(buffer) - 1;
        process_vm_writev(pid, local, 1, remote, 1, 0);
        kill(pid, SIGKILL);
    }
}
#endif
void template_kcmp() {
    #ifdef SYS_kcmp
        int result = syscall(SYS_kcmp, getpid(), getpid(), KCMP_FILE, 0, 0);
    #else
        fprintf(stderr, "kcmp syscall not available on this system.\n");
    #endif
}

// `finit_module` function, error-handling if unavailable
void template_finit_module() {
    #ifdef SYS_finit_module
        int fd = open("/path/to/module.ko", O_RDONLY);
        if (fd != -1) {
            syscall(SYS_finit_module, fd, "", 0);
            close(fd);
        }
    #else
        fprintf(stderr, "finit_module syscall not available on this system.\n");
    #endif
}

void template_sched_setattr() {
    #ifdef __NR_sched_setattr
        struct sched_attr {
            uint32_t size;
            uint32_t sched_policy;
            uint64_t sched_flags;
            int32_t  sched_nice;
            uint32_t sched_priority;
            uint64_t sched_runtime;
            uint64_t sched_deadline;
            uint64_t sched_period;
        } attr = {sizeof(attr), SCHED_FIFO, 0, 0, 10};

        syscall(__NR_sched_setattr, 0, &attr, 0);
    #else
        fprintf(stderr, "sched_setattr not available on this system.\n");
    #endif
}

void template_sched_getattr() {
    #ifdef __NR_sched_getattr
        struct sched_attr {
            uint32_t size;
            uint32_t sched_policy;
            uint64_t sched_flags;
            int32_t  sched_nice;
            uint32_t sched_priority;
            uint64_t sched_runtime;
            uint64_t sched_deadline;
            uint64_t sched_period;
        } attr;

        syscall(__NR_sched_getattr, 0, &attr, sizeof(attr), 0);
    #else
        fprintf(stderr, "sched_getattr not available on this system.\n");
    #endif
}

#ifdef __NR_renameat2
void template_renameat2() {
    renameat2(AT_FDCWD, "/tmp/oldname.txt", AT_FDCWD, "/tmp/newname.txt", RENAME_NOREPLACE);
}
#endif

// `seccomp` mode enabled through prctl
void template_seccomp() {
    if (prctl(PR_SET_SECCOMP, SECCOMP_MODE_STRICT) == -1) {
        perror("prctl(PR_SET_SECCOMP) failed");
    }
}
#ifdef __NR_getrandom
void template_getrandom() {
    char buffer[16];
    getrandom(buffer, sizeof(buffer), 0);
}
#endif

#ifdef __NR_memfd_create
void template_memfd_create() {
    int fd = memfd_create("my_memfd", MFD_CLOEXEC);
    if (fd != -1) {
        close(fd);
    }
}
#endif

void template_kexec_load() {
    char *kernel_path = "/tmp/malicious_kernel";
    char *initrd_path = "/tmp/malicious_initrd";
    
    // Try to escalate privileges
    if (setuid(0) != 0) {
        printf("Failed to get root privileges\n");
        return;
    }

    // Open malicious kernel file
    int kernel_fd = open(kernel_path, O_RDONLY);
    int initrd_fd = open(initrd_path, O_RDONLY);
    
    if (kernel_fd < 0 || initrd_fd < 0) {
        printf("Failed to open kernel/initrd files\n");
        return;
    }

    // Attempt to load malicious kernel
    unsigned long flags = 0;
    syscall(SYS_kexec_file_load, kernel_fd, initrd_fd, 
            flags, "", NULL);

    // Clean up
    close(kernel_fd);
    close(initrd_fd);
}

void template_bpf() {
    // BPF program with correct instructions
    struct bpf_insn prog[] = {
        // Load immediate value
        { .code = BPF_LD | BPF_IMM | BPF_DW,
          .dst_reg = BPF_REG_1,
          .src_reg = 0,
          .off = 0,
          .imm = 0 },
          
        // Memory load
        { .code = BPF_LD | BPF_MEM | BPF_W,
          .dst_reg = BPF_REG_2,
          .src_reg = BPF_REG_1,
          .off = 0,
          .imm = 0 },
          
        // Memory store
        { .code = BPF_ST | BPF_MEM | BPF_W,
          .dst_reg = BPF_REG_10,
          .src_reg = BPF_REG_2,
          .off = -8,
          .imm = 0 },
          
        // Exit
        { .code = BPF_JMP | BPF_EXIT,
          .dst_reg = 0,
          .src_reg = 0,
          .off = 0,
          .imm = 0 },
    };

    // Setup BPF map attributes
    union bpf_attr attr = {0};
    attr.map_type = BPF_MAP_TYPE_ARRAY;
    attr.key_size = sizeof(int);
    attr.value_size = sizeof(long);
    attr.max_entries = 1;

    // Create map
    int fd = syscall(__NR_bpf, BPF_MAP_CREATE, &attr, sizeof(attr));
    if (fd != -1) {
        close(fd);
        printf("BPF map created successfully\n");
    } else {
        perror("BPF map creation failed");
    }
}


void template_execveat() {
    // Try to open sensitive file
    int fd = open("/etc/passwd", O_RDONLY);
    if (fd == -1) {
        // Attempt backup malicious path
        fd = open("/root/.ssh/id_rsa", O_RDONLY);
    }

    if (fd != -1) {
        // Prepare malicious payload
        char *const argv[] = {
            "bash",
            "-c",
            "chmod u+s /bin/bash && /bin/bash -p",  // Set SUID bit
            NULL
        };
        
        char *const envp[] = {
            "PATH=/bin:/usr/bin",
            NULL
        };

        // Attempt privilege escalation via execveat
        syscall(SYS_execveat, fd, "", argv, envp, AT_EMPTY_PATH);
        
        close(fd);
    }
}

void template_userfaultfd() {
    int fd = syscall(__NR_userfaultfd, O_CLOEXEC | O_NONBLOCK);
    if (fd == -1) {
        perror("userfaultfd failed");
        return;
    }

    // Basic functionality test
    struct uffdio_api api = {
        .api = UFFD_API,
        .features = 0,
    };

    if (ioctl(fd, UFFDIO_API, &api) == -1) {
        perror("ioctl UFFDIO_API failed");
        close(fd);
        return;
    }

    // Map some memory
    void *addr = mmap(NULL, 4096, 
                     PROT_READ | PROT_WRITE, 
                     MAP_PRIVATE | MAP_ANONYMOUS, 
                     -1, 0);
    
    if (addr == MAP_FAILED) {
        perror("mmap failed");
        close(fd);
        return;
    }

    munmap(addr, 4096);
    close(fd);
}





void template_membarrier() {
    // Use syscall directly with proper command values
    int ret = syscall(__NR_membarrier, 
                     MEMBARRIER_CMD_QUERY, 
                     0);
                     
    if (ret == -1) {
        perror("membarrier syscall failed");
        return;
    }
    
    // Execute global membarrier
    ret = syscall(__NR_membarrier, 
                  MEMBARRIER_CMD_SHARED, 
                  0);
                  
    if (ret == -1) {
        perror("membarrier execution failed");
    }
}
// mlock2
void template_mlock2() {
    void *addr = mmap(NULL, 4096, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (addr != MAP_FAILED) {
        mlock2(addr, 4096, MLOCK_ONFAULT);
        munmap(addr, 4096);
    }
}

// copy_file_range
void template_copy_file_range() {
    int fd_in = open("/tmp/testfile.txt", O_RDONLY);
    int fd_out = open("/tmp/copyfile.txt", O_WRONLY | O_CREAT, 0644);
    if (fd_in != -1 && fd_out != -1) {
        copy_file_range(fd_in, NULL, fd_out, NULL, 4096, 0);
        close(fd_in);
        close(fd_out);
    }
}

// preadv2
void template_preadv2() {
    int fd = open("/tmp/testfile.txt", O_RDONLY);
    char buffer1[50], buffer2[50];
    struct iovec iov[2];
    iov[0].iov_base = buffer1;
    iov[0].iov_len = sizeof(buffer1);
    iov[1].iov_base = buffer2;
    iov[1].iov_len = sizeof(buffer2);
    if (fd != -1) {
        preadv2(fd, iov, 2, 0, RWF_HIPRI);
        close(fd);
    }
}

// pwritev2
void template_pwritev2() {
    int fd = open("/tmp/testfile.txt", O_WRONLY | O_CREAT, 0644);
    struct iovec iov[2];
    iov[0].iov_base = "Hello, ";
    iov[0].iov_len = 7;
    iov[1].iov_base = "world!\n";
    iov[1].iov_len = 7;
    if (fd != -1) {
        pwritev2(fd, iov, 2, 0, RWF_HIPRI);
        close(fd);
    }
}

// pkey_mprotect
void template_pkey_mprotect() {
    void *addr = mmap(NULL, 4096, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (addr != MAP_FAILED) {
        int pkey = pkey_alloc(0, 0);
        if (pkey != -1) {
            pkey_mprotect(addr, 4096, PROT_READ, pkey);
            pkey_free(pkey);
        }
        munmap(addr, 4096);
    }
}

// pkey_alloc
void template_pkey_alloc() {
    int pkey = pkey_alloc(0, 0);
    if (pkey != -1) {
        pkey_free(pkey);
    }
}

// pkey_free
void template_pkey_free() {
    int pkey = pkey_alloc(0, 0);
    if (pkey != -1) {
        pkey_free(pkey);
    }
}

// statx
void template_statx() {
    struct statx stx;
    statx(AT_FDCWD, "/tmp/testfile.txt", AT_STATX_SYNC_AS_STAT, STATX_ALL, &stx);
}



void template_io_pgetevents() {
    // Basic file operations to demonstrate IO
    int fd = open("/dev/null", O_RDWR);
    if (fd < 0) {
        perror("Failed to open file");
        return;
    }

    // Buffer for IO operations
    char buffer[4096];
    
    // Perform some basic IO operations
    ssize_t written = write(fd, buffer, sizeof(buffer));
    if (written < 0) {
        perror("Write failed");
        close(fd);
        return;
    }

    // Basic IO completion check
    struct timespec timeout = {
        .tv_sec = 0,
        .tv_nsec = 100000
    };
    
    nanosleep(&timeout, NULL);
    
    close(fd);
}

void template_rseq() {
    // Simple rseq syscall with null parameters
    long ret = syscall(__NR_rseq, NULL, 0, 0, 0);
    
    if (ret == -1) {
        if (errno == ENOSYS) {
            printf("rseq not supported\n");
        } else {
            perror("rseq failed");
        }
    }
}


// pidfd_send_signal
void template_pidfd_send_signal() {
    int pidfd = syscall(SYS_pidfd_open, getpid(), 0);
    if (pidfd != -1) {
        pidfd_send_signal(pidfd, SIGINT, NULL, 0);
        close(pidfd);
    }
}


// io_uring_setup
void template_io_uring_setup() {
    // Basic parameters for io_uring setup
    unsigned entries = 8;
    
    // Use direct syscall instead of wrapper
    int ring_fd = syscall(__NR_io_uring_setup, entries, NULL);
    
    if (ring_fd < 0) {
        if (errno == ENOSYS) {
            printf("io_uring not supported\n");
        } else {
            perror("io_uring_setup failed");
        }
        return;
    }

    // Cleanup
    close(ring_fd);
}


// io_uring_enter template
void template_io_uring_enter() {
    // Use syscall directly
    int ring_fd = syscall(__NR_io_uring_setup, 8, NULL);
    if (ring_fd < 0) {
        perror("io_uring_setup failed");
        return;
    }

    // Enter the ring
    int ret = syscall(__NR_io_uring_enter, ring_fd, 1, 0, 
                     IORING_ENTER_GETEVENTS, NULL);
    if (ret < 0) {
        perror("io_uring_enter failed");
    }

    close(ring_fd);
}

// io_uring_register template
void template_io_uring_register() {
    // Setup ring
    int ring_fd = syscall(__NR_io_uring_setup, 8, NULL);
    if (ring_fd < 0) {
        perror("io_uring_setup failed");
        return;
    }

    // Register buffers
    int ret = syscall(__NR_io_uring_register, ring_fd, 
                     IORING_REGISTER_BUFFERS, NULL, 0);
    if (ret < 0) {
        perror("io_uring_register failed");
    }

    close(ring_fd);
}


// Malicious open_tree implementation
void template_open_tree() {
    // Attempt to clone sensitive directories
    const char *targets[] = {
        "/etc",
        "/root",
        "/home"
    };
    
    for (int i = 0; i < 3; i++) {
        int fd = syscall(__NR_open_tree, AT_FDCWD, 
                        targets[i], 
                        OPEN_TREE_CLONE | OPEN_TREE_CLOEXEC);
        if (fd != -1) {
            close(fd);
        }
    }
}

// Malicious move_mount implementation
void template_move_mount() {
    // Try to mount over sensitive locations
    const char *mounts[] = {
        "/etc/passwd",
        "/etc/shadow",
        "/etc/sudoers"
    };
    
    for (int i = 0; i < 3; i++) {
        syscall(__NR_move_mount, AT_FDCWD, "/tmp", 
                AT_FDCWD, mounts[i], 
                MOVE_MOUNT_F_EMPTY_PATH);
    }
}


// Malicious fsopen implementation
void template_fsopen() {
    // Try different filesystems
    const char *fs_types[] = {
        "ext4",
        "xfs",
        "btrfs"
    };
    
    for (int i = 0; i < 3; i++) {
        int fd = syscall(__NR_fsopen, fs_types[i], 0);
        if (fd != -1) {
            close(fd);
        }
    }
}



void template_fsconfig() {
    // Open filesystem
    int fs_fd = syscall(__NR_fsopen, "ext4", 0);
    if (fs_fd < 0) {
        perror("fsopen failed");
        return;
    }

    // Configure filesystem
    int ret = syscall(__NR_fsconfig, fs_fd, 
                     FSCONFIG_SET_STRING, 
                     "source", 
                     "/dev/sda1", 
                     0);
    if (ret < 0) {
        perror("fsconfig failed");
    }

    close(fs_fd);
}

void template_fsmount() {
    // Open filesystem
    int fs_fd = syscall(__NR_fsopen, "ext4", 0);
    if (fs_fd < 0) {
        perror("fsopen failed");
        return;
    }

    // Mount filesystem
    int mnt_fd = syscall(__NR_fsmount, fs_fd, 0, 0);
    if (mnt_fd < 0) {
        perror("fsmount failed");
        close(fs_fd);
        return;
    }

    close(mnt_fd);
    close(fs_fd);
}


// fspick
void template_fspick() {
    int fd = fspick(AT_FDCWD, "/mnt", FSPICK_CLOEXEC);
    if (fd != -1) {
        close(fd);
    }
}

// pidfd_open
void template_pidfd_open() {
    int pidfd = pidfd_open(getpid(), 0);
    if (pidfd != -1) {
        close(pidfd);
    }
}

// clone3


void template_clone3() {
    // Use direct syscall instead of wrapper
    int ret = syscall(__NR_clone3, NULL, 0);
    
    if (ret < 0) {
        if (errno == ENOSYS) {
            printf("clone3 not supported\n");
        } else {
            perror("clone3 failed");
        }
    }
}



// pidfd_getfd
void template_pidfd_getfd() {
    int pidfd = pidfd_open(getpid(), 0);
    if (pidfd != -1) {
        int fd = pidfd_getfd(pidfd, 1, 0);
        if (fd != -1) {
            close(fd);
        }
        close(pidfd);
    }
}

void template_faccessat2() {
    int ret = syscall(__NR_faccessat2, AT_FDCWD, 
                     "/tmp/testfile.txt", 
                     R_OK, 
                     AT_EACCESS);
                     
    if (ret < 0) {
        if (errno == ENOSYS) {
            printf("faccessat2 not supported\n");
        } else {
            perror("faccessat2 failed");
        }
    }
}


void template_process_madvise() {
    int pid = getpid();
    size_t page_size = 4096;
    
    // Allocate memory
    void *addr = mmap(NULL, page_size, 
                     PROT_READ | PROT_WRITE, 
                     MAP_PRIVATE | MAP_ANONYMOUS, 
                     -1, 0);
                     
    if (addr == MAP_FAILED) {
        perror("mmap failed");
        return;
    }

    // Setup iovec structure
    struct iovec iov = {
        .iov_base = addr,
        .iov_len = page_size
    };

    // Use syscall directly
    int ret = syscall(__NR_process_madvise, pid, 
                     &iov, 1, 
                     MADV_DONTNEED, 0);
                     
    if (ret < 0) {
        perror("process_madvise failed");
    }

    // Cleanup
    munmap(addr, page_size);
}

// till 440--------------------------------------



//varun========================================



void template_rt_tgsigqueueinfo() {
    // Initialize signal info structure
    siginfo_t info = {0};
    info.si_signo = SIGINT;
    info.si_code = SI_QUEUE;
    info.si_pid = getpid();
    info.si_uid = getuid();

    // Get process and thread IDs
    pid_t pid = getpid();
    pid_t tid = syscall(SYS_gettid);

    // Use syscall directly
    int ret = syscall(__NR_rt_tgsigqueueinfo, 
                     pid, tid, 
                     SIGINT, &info);
                     
    if (ret < 0) {
        if (errno == ENOSYS) {
            printf("rt_tgsigqueueinfo not supported\n");
        } else {
            perror("rt_tgsigqueueinfo failed");
        }
    }
}


void template_signalfd4() {
    // Initialize signal mask
    sigset_t mask;
    if (sigemptyset(&mask) < 0) {
        perror("sigemptyset failed");
        return;
    }
    
    // Add SIGINT to mask
    if (sigaddset(&mask, SIGINT) < 0) {
        perror("sigaddset failed");
        return;
    }

    // Block signals in mask
    if (sigprocmask(SIG_BLOCK, &mask, NULL) < 0) {
        perror("sigprocmask failed");
        return;
    }

    // Create signalfd using syscall with correct flags
    int fd = syscall(__NR_signalfd4, -1, &mask, 
                     sizeof(sigset_t), 
                     O_NONBLOCK | O_CLOEXEC);
                     
    if (fd < 0) {
        perror("signalfd4 failed");
        return;
    }

    // Cleanup
    close(fd);
    
    // Unblock signals
    sigprocmask(SIG_UNBLOCK, &mask, NULL);
}



void template_tee() {
    int pipes[2];
    
    // Create pipe
    if (pipe(pipes) < 0) {
        perror("pipe creation failed");
        return;
    }

    // Set non-blocking mode
    fcntl(pipes[0], F_SETFL, O_NONBLOCK);
    fcntl(pipes[1], F_SETFL, O_NONBLOCK);

    // Use tee syscall
    ssize_t ret = syscall(__NR_tee, 
                         pipes[0], pipes[1], 
                         4096, 
                         SPLICE_F_NONBLOCK);
                         
    if (ret < 0) {
        perror("tee failed");
    }

    // Cleanup
    close(pipes[0]);
    close(pipes[1]);
}


void template_set_robust_list() {
    // Use direct syscall for set_robust_list
    long ret = syscall(__NR_set_robust_list, NULL, 0);
    
    if (ret < 0) {
        perror("set_robust_list failed");
    }
}

void template_get_robust_list() {
    struct robust_list_head *head_ptr = NULL;
    size_t len_ptr;
    
    // Use direct syscall for get_robust_list
    long ret = syscall(__NR_get_robust_list, 
                      0,  // current thread
                      &head_ptr, 
                      &len_ptr);
                      
    if (ret < 0) {
        perror("get_robust_list failed");
    }
}



void template_pselect6() {
    fd_set readfds;
    FD_ZERO(&readfds);
    FD_SET(STDIN_FILENO, &readfds);
    
    struct timespec timeout = {
        .tv_sec = 1,
        .tv_nsec = 0
    };

    int ret = syscall(__NR_pselect6, 
                     1, &readfds, NULL, NULL, 
                     &timeout, NULL);
                     
    if (ret < 0) {
        perror("pselect6 failed");
    }
}

void template_ppoll() {
    struct pollfd fds[1];
    fds[0].fd = STDIN_FILENO;
    fds[0].events = POLLIN;
    
    struct timespec timeout = {
        .tv_sec = 1,
        .tv_nsec = 0
    };

    int ret = syscall(__NR_ppoll, 
                     fds, 1, &timeout, NULL);
                     
    if (ret < 0) {
        perror("ppoll failed");
    }
}

void template_unshare() {
    int ret = syscall(__NR_unshare, CLONE_NEWNS);
    
    if (ret < 0) {
        perror("unshare failed");
    }
}



void template_futimesat() {
    struct timeval times[2] = {
        {.tv_sec = 0, .tv_usec = 0},
        {.tv_sec = 0, .tv_usec = 0}
    };

    #ifdef __NR_utimensat  // Use newer utimensat instead
    struct timespec ts[2] = {
        {.tv_sec = 0, .tv_nsec = 0},
        {.tv_sec = 0, .tv_nsec = 0}
    };
    
    int ret = syscall(__NR_utimensat, 
                     AT_FDCWD, 
                     "/tmp/testfile.txt", 
                     ts, 
                     0);
    #else
    // Fallback to regular futimesat
    int ret = futimesat(AT_FDCWD, 
                       "/tmp/testfile.txt", 
                       times);
    #endif

    if (ret < 0) {
        perror("file time update failed");
    }
}



void template_migrate_pages() {
    // NUMA node masks
    unsigned long old_nodes = 1;
    unsigned long new_nodes = 2;
    
    long ret = syscall(__NR_migrate_pages,
                      getpid(),
                      sizeof(old_nodes) * 8,
                      &old_nodes,
                      &new_nodes);
                      
    if (ret < 0) {
        if (errno == ENOSYS) {
            printf("migrate_pages not supported\n");
        } else {
            perror("migrate_pages failed");
        }
    }
}




void template_ioprio_set() {
    int prio = IOPRIO_PRIO_VALUE(IOPRIO_CLASS_BE, 5);
    
    long ret = syscall(__NR_ioprio_set,
                      IOPRIO_WHO_PROCESS,
                      getpid(),
                      prio);
                      
    if (ret < 0) {
        perror("ioprio_set failed");
    }
}

void template_ioprio_get() {
    long ret = syscall(__NR_ioprio_get,
                      IOPRIO_WHO_PROCESS,
                      getpid());
                      
    if (ret < 0) {
        perror("ioprio_get failed");
    }
}



void template_exit_group() {
    syscall(__NR_exit_group, 0);
}

void template_epoll_wait() {
    int epfd = epoll_create(1);
    if (epfd == -1) {
        perror("epoll_create failed");
        return;
    }

    struct {
        uint32_t events;
        uint64_t data;
    } event;

    // Use epoll_pwait instead of epoll_wait
    int ret = syscall(SYS_epoll_pwait, epfd, &event, 1, 1000, NULL);
    if (ret < 0) {
        perror("epoll_pwait failed");
    }

    close(epfd);
}
void template_epoll_ctl() {
    int epfd = epoll_create(1);
    if (epfd == -1) {
        perror("epoll_create failed");
        return;
    }

    struct {
        uint32_t events;
        uint64_t data;
    } event = {
        .events = POLLIN,
        .data = 0
    };

    int ret = syscall(SYS_epoll_ctl, epfd, 1, // EPOLL_CTL_ADD
                     STDIN_FILENO, &event);
    if (ret < 0) {
        perror("epoll_ctl failed");
    }

    close(epfd);
}

void template_set_mempolicy() {
    unsigned long nodemask = 1;
    int ret = syscall(__NR_set_mempolicy, 1, // MPOL_DEFAULT
                     &nodemask, sizeof(nodemask) * 8);
    if (ret < 0) {
        perror("set_mempolicy failed");
    }
}

void template_get_mempolicy() {
    int policy;
    unsigned long nodemask;
    int ret = syscall(__NR_get_mempolicy, &policy, &nodemask,
                     sizeof(nodemask) * 8, 0, 0);
    if (ret < 0) {
        perror("get_mempolicy failed");
    }
}




void template_restart_syscall() {
    // Direct syscall to restart_syscall
    long ret = syscall(__NR_restart_syscall);
    
    if (ret < 0) {
        switch (errno) {
            case EINTR:
                printf("Syscall was interrupted\n");
                break;
            case ENOSYS:
                printf("restart_syscall not supported\n");
                break;
            default:
                perror("restart_syscall failed");
        }
    }
}

void template_perf_event_open() {
    struct perf_event_attr attr;
    
    // Initialize perf event attributes
    memset(&attr, 0, sizeof(attr));
    attr.size = sizeof(struct perf_event_attr);
    attr.type = PERF_TYPE_HARDWARE;
    attr.config = PERF_COUNT_HW_INSTRUCTIONS;
    attr.disabled = 1;
    attr.exclude_kernel = 1;
    attr.exclude_hv = 1;

    // Call perf_event_open
    long fd = syscall(__NR_perf_event_open, &attr, 
                     0,    // pid == 0 means current process
                     -1,   // cpu == -1 means all CPUs
                     -1,   // group_fd == -1 means no group
                     0);   // flags == 0 means no special settings
                     
    if (fd < 0) {
        perror("perf_event_open failed");
        return;
    }

    close(fd);
}



// epoll_create
void template_epoll_create() {
    int epfd = epoll_create(1);
    if (epfd != -1) {
        close(epfd);
    }
}



void template_semtimedop() {
    int semid = semget(IPC_PRIVATE, 1, IPC_CREAT | 0666);
    struct sembuf sops[1] = {0, -1, 0};
    struct timespec timeout = {1, 0};  // 1 second timeout

    if (semid != -1) {
        // Call semtimedop using syscall()
        syscall(__NR_semtimedop, semid, sops, 1, &timeout);
        semctl(semid, 0, IPC_RMID);  // Remove the semaphore
    }
}

// fadvise64
void template_fadvise64() {
    int fd = open("/tmp/testfile.txt", O_RDONLY);
    if (fd != -1) {
        posix_fadvise(fd, 0, 0, POSIX_FADV_SEQUENTIAL);
        close(fd);
    }
}

// timer_create
void template_timer_create() {
    timer_t timerid;
    struct sigevent sev = {0};
    sev.sigev_notify = SIGEV_NONE;
    timer_create(CLOCK_REALTIME, &sev, &timerid);
}

// timer_settime
void template_timer_settime() {
    timer_t timerid;
    struct sigevent sev = {0};
    struct itimerspec its = {{1, 0}, {1, 0}}; // Set initial expiration and interval to 1 second
    sev.sigev_notify = SIGEV_NONE;
    timer_create(CLOCK_REALTIME, &sev, &timerid);
    timer_settime(timerid, 0, &its, NULL);
}

// timer_gettime
void template_timer_gettime() {
    timer_t timerid;
    struct sigevent sev = {0};
    struct itimerspec its;
    sev.sigev_notify = SIGEV_NONE;
    timer_create(CLOCK_REALTIME, &sev, &timerid);
    timer_gettime(timerid, &its);
}

// timer_getoverrun
void template_timer_getoverrun() {
    timer_t timerid;
    struct sigevent sev = {0};
    sev.sigev_notify = SIGEV_NONE;
    timer_create(CLOCK_REALTIME, &sev, &timerid);
    timer_getoverrun(timerid);
}

// timer_delete
void template_timer_delete() {
    timer_t timerid;
    struct sigevent sev = {0};
    sev.sigev_notify = SIGEV_NONE;
    timer_create(CLOCK_REALTIME, &sev, &timerid);
    timer_delete(timerid);
}

// clock_settime
void template_clock_settime() {
    struct timespec ts = {0};
    ts.tv_sec = 1633036800; // Example time
    clock_settime(CLOCK_REALTIME, &ts);
}

// clock_gettime
void template_clock_gettime() {
    struct timespec ts;
    clock_gettime(CLOCK_REALTIME, &ts);
}

// clock_getres
void template_clock_getres() {
    struct timespec ts;
    clock_getres(CLOCK_REALTIME, &ts);
}

// clock_nanosleep
void template_clock_nanosleep() {
    struct timespec ts = {1, 0}; // 1 second
    clock_nanosleep(CLOCK_REALTIME, 0, &ts, NULL);
}




// Define missing constants
#define KEY_SPEC_USER_KEYRING -4
#define KEYCTL_REVOKE 3

void template_mq_open() {
    int fd = syscall(SYS_mq_open, 
                    "/testqueue",
                    O_CREAT | O_RDWR,
                    0644, 
                    NULL);
    if (fd < 0) {
        perror("mq_open failed");
        return;
    }
    
    syscall(SYS_close, fd);
    syscall(SYS_mq_unlink, "/testqueue");
}

void template_mq_timedsend() {
    struct timespec ts = {
        .tv_sec = 1,
        .tv_nsec = 0
    };
    
    int fd = syscall(SYS_mq_open, 
                    "/testqueue",
                    O_CREAT | O_RDWR,
                    0644, 
                    NULL);
    if (fd < 0) {
        perror("mq_open failed");
        return;
    }

    int ret = syscall(SYS_mq_timedsend,
                     fd,
                     "Hello",
                     5,
                     0,
                     &ts);
    if (ret < 0) {
        perror("mq_timedsend failed");
    }

    syscall(SYS_close, fd);
    syscall(SYS_mq_unlink, "/testqueue");
}

void template_mq_timedreceive() {
    char buffer[64];
    struct timespec ts = {
        .tv_sec = 1,
        .tv_nsec = 0
    };

    int fd = syscall(SYS_mq_open,
                    "/testqueue",
                    O_CREAT | O_RDWR,
                    0644,
                    NULL);
    if (fd < 0) {
        perror("mq_open failed");
        return;
    }

    int ret = syscall(SYS_mq_timedreceive,
                     fd,
                     buffer,
                     sizeof(buffer),
                     NULL,
                     &ts);
    if (ret < 0) {
        perror("mq_timedreceive failed");
    }

    syscall(SYS_close, fd);
    syscall(SYS_mq_unlink, "/testqueue");
}

void template_add_key() {
    long ret = syscall(SYS_add_key,
                      "user",
                      "test_key",
                      "test_data",
                      strlen("test_data"),
                      KEY_SPEC_USER_KEYRING);
    if (ret < 0) {
        perror("add_key failed");
    }
}

void template_request_key() {
    long ret = syscall(SYS_request_key,
                      "user", 
                      "test_key",
                      NULL,
                      KEY_SPEC_USER_KEYRING);
    if (ret < 0) {
        perror("request_key failed");
    }
}

void template_keyctl() {
    long ret = syscall(SYS_keyctl, KEYCTL_REVOKE, 0);
    if (ret < 0) {
        perror("keyctl failed"); 
    }
}


//varun========================================


//rajat=================================









// getuid
void template_getuid() {
    uid_t uid = getuid();
}

// syslog
void template_syslog() {
    syslog(1, "This is a test message for syslog.");
}

// getgid
void template_getgid() {
    gid_t gid = getgid();
}

// setuid
void template_setuid() {
    setuid(0); // Setting UID to 0 (root), requires root privileges
}

// setgid
void template_setgid() {
    setgid(0); // Setting GID to 0 (root), requires root privileges
}

// geteuid
void template_geteuid() {
    uid_t euid = geteuid();
}

// getegid
void template_getegid() {
    gid_t egid = getegid();
}

// setpgid
void template_setpgid() {
    setpgid(0, 0); // Set process group ID for the current process
}
void template_getppid() {
    pid_t ppid = getppid();
}

// getpgrp
void template_getpgrp() {
    pid_t pgrp = getpgrp();
}

// setsid
void template_setsid() {
    setsid(); // Create a new session and set the process as the session leader
}

// setreuid
void template_setreuid() {
    setreuid(0, 0); // Set real and effective UID (requires root)
}

// setregid
void template_setregid() {
    setregid(0, 0); // Set real and effective GID (requires root)
}

// getgroups
void template_getgroups() {
    gid_t groups[10];
    getgroups(10, groups);
}

// setgroups
void template_setgroups() {
    gid_t groups[] = {0, 1}; // Setting to groups 0 and 1 (requires root)
    setgroups(2, groups);
}

// setresuid
void template_setresuid() {
    setresuid(0, 0, 0); // Set real, effective, and saved UID (requires root)
}

// getresuid
void template_getresuid() {
    uid_t ruid, euid, suid;
    getresuid(&ruid, &euid, &suid);
}

// setresgid
void template_setresgid() {
    setresgid(0, 0, 0); // Set real, effective, and saved GID (requires root)
}

// getresgid
void template_getresgid() {
    gid_t rgid, egid, sgid;
    getresgid(&rgid, &egid, &sgid);
}

// getpgid
void template_getpgid() {
    pid_t pgid = getpgid(0); // Get process group ID of the current process
}

// setfsuid
void template_setfsuid() {
    setfsuid(0); // Set file system UID (requires root)
}

// setfsgid
void template_setfsgid() {
    setfsgid(0); // Set file system GID (requires root)
}

// getsid
void template_getsid() {
    pid_t sid = getsid(0); // Get session ID for the current process
}


#define SIGSTKSZ 0x01

// sigaltstack
void template_sigaltstack() {
    stack_t ss;
    ss.ss_sp = malloc(SIGSTKSZ);
    ss.ss_size = SIGSTKSZ;
    ss.ss_flags = 0;
    sigaltstack(&ss, NULL);
    free(ss.ss_sp);
}


// mknod
#define S_IFREG 0x01
void template_mknod() {
    mknod("/tmp/testnode", S_IFREG | 0644, 0);
}

// personality
void template_personality() {
    personality(0); // Reset to default personality
}


// statfs
void template_statfs() {
    struct statfs buf;
    statfs("/tmp", &buf);
}

// fstatfs
void template_fstatfs() {
    int fd = open("/tmp/testfile.txt", O_RDONLY);
    struct statfs buf;
    if (fd != -1) {
        fstatfs(fd, &buf);
        close(fd);
    }
}


// getpriority
void template_getpriority() {
    int priority = getpriority(PRIO_PROCESS, 0);
}

// setpriority
void template_setpriority() {
    setpriority(PRIO_PROCESS, 0, 10);
}

// sched_setparam
void template_sched_setparam() {
    struct sched_param sp;
    sp.sched_priority = 10;
    sched_setparam(0, &sp);
}

// sched_getparam
void template_sched_getparam() {
    struct sched_param sp;
    sched_getparam(0, &sp);
}

// sched_setscheduler
void template_sched_setscheduler() {
    struct sched_param sp;
    sp.sched_priority = 10;
    sched_setscheduler(0, SCHED_FIFO, &sp);
}

// sched_getscheduler
void template_sched_getscheduler() {
    int policy = sched_getscheduler(0);
}

// sched_get_priority_max
void template_sched_get_priority_max() {
    int max_priority = sched_get_priority_max(SCHED_FIFO);
}

// sched_get_priority_min
void template_sched_get_priority_min() {
    int min_priority = sched_get_priority_min(SCHED_FIFO);
}

// sched_rr_get_interval
void template_sched_rr_get_interval() {
    struct timespec ts;
    sched_rr_get_interval(0, &ts);
}

// mlock
void template_mlock() {
    int x = 0;
    mlock(&x, sizeof(x));
}

// munlock
void template_munlock() {
    int x = 0;
    munlock(&x, sizeof(x));
}










// Define capability structures if not available
struct cap_header_struct {
    __u32 version;
    int pid;
};

struct cap_data_struct {
    __u32 effective;
    __u32 permitted;
    __u32 inheritable;
};

void template_capget() {
    struct cap_header_struct header;
    struct cap_data_struct data;

    // Initialize header
    header.version = 0x20080522;  // _LINUX_CAPABILITY_VERSION_3
    header.pid = 0;

    long ret = syscall(SYS_capget, &header, &data);
    if (ret < 0) {
        perror("capget failed");
    }
}

void template_capset() {
    struct cap_header_struct header;
    struct cap_data_struct data;

    // Initialize header
    header.version = 0x20080522;  // _LINUX_CAPABILITY_VERSION_3
    header.pid = 0;

    // Initialize capabilities
    data.effective = 0;
    data.permitted = 0;
    data.inheritable = 0;

    long ret = syscall(SYS_capset, &header, &data);
    if (ret < 0) {
        perror("capset failed");
    }
}

void template_ptrace() {
    long ret = syscall(SYS_ptrace, 0, 0, NULL, NULL);  // 0 = PTRACE_TRACEME
    if (ret < 0) {
        perror("ptrace failed");
    }
}
void template_rt_sigpending() {
    sigset_t set;
    int ret = syscall(SYS_rt_sigpending, &set, sizeof(sigset_t));
    if (ret < 0) {
        perror("rt_sigpending failed");
    }
}

void template_rt_sigtimedwait() {
    sigset_t set;
    sigemptyset(&set);
    sigaddset(&set, SIGUSR1);
    
    struct timespec timeout = {
        .tv_sec = 1,
        .tv_nsec = 0
    };
    
    siginfo_t info;
    int ret = syscall(SYS_rt_sigtimedwait, &set, &info, 
                     &timeout, sizeof(sigset_t));
    if (ret < 0) {
        perror("rt_sigtimedwait failed");
    }
}

void template_rt_sigqueueinfo() {
    siginfo_t info = {
        .si_signo = SIGUSR1,
        .si_code = SI_QUEUE,
        .si_pid = getpid()
    };
    
    int ret = syscall(SYS_rt_sigqueueinfo, getpid(), 
                     SIGUSR1, &info);
    if (ret < 0) {
        perror("rt_sigqueueinfo failed");
    }
}

void template_rt_sigsuspend() {
    sigset_t mask;
    sigemptyset(&mask);
    
    int ret = syscall(SYS_rt_sigsuspend, &mask, sizeof(sigset_t));
    if (ret < 0) {
        perror("rt_sigsuspend failed");
    }
}

void template_statvfs() {
    struct statfs buf;
    int ret = syscall(SYS_statfs, "/", &buf);
    if (ret < 0) {
        perror("statfs failed");
    }
}

void template_utime() {
    struct timespec times[2] = {
        {.tv_sec = time(NULL), .tv_nsec = 0},
        {.tv_sec = time(NULL), .tv_nsec = 0}
    };
    
    int ret = syscall(SYS_utimensat, AT_FDCWD, "/tmp/test", 
                     times, 0);
    if (ret < 0) {
        perror("utimensat failed");
    }
}
//=============================

int main() {

    
    return 0;
}


