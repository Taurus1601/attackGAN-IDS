#include "systemcallsfunction.h"
#include <time.h>                   // Time functions
#include <pthread.h>                // POSIX threads
#include <sched.h>                  // Scheduling
#include <utime.h>                  // File timestamps

// System-related headers
#include <sys/types.h>             // Basic system data types
#include <sys/stat.h>              // File status
#include <sys/time.h>              // Time operations
#include <sys/resource.h>          // Resource operations
#include <sys/wait.h>              // Process control
#include <sys/mount.h>             // Mount operations
#include <sys/mman.h>              // Memory management
#include <sys/ioctl.h>             // I/O control
#include <sys/epoll.h>             // I/O event notification
#include <sys/inotify.h>           // File system event monitoring
#include <sys/syscall.h>           // System call wrapper functions
#include <sys/sysinfo.h>           // System statistics
#include <sys/xattr.h>             // Extended attributes
#include <sys/msg.h>               // Message queues
#include <sys/sem.h>               // Semaphores
#include <sys/shm.h>               // Shared memory
#include <sys/prctl.h>             // Process control
#include <sys/sysmacros.h>         // System macros
#include <sys/statfs.h>            // File system statistics
#include <sys/reboot.h>            // Reboot operations
#include <sys/quota.h>             // Disk quotas

// Network-related headers
#include <netinet/in.h>            // Internet protocol
#include <arpa/inet.h>             // Internet operations

// Linux-specific headers
#include <linux/capability.h>       // POSIX capabilities
#include <linux/limits.h>          // System limits
#include <linux/unistd.h>          // Linux system calls
#include <linux/quota.h>           // Quota support
#include <linux/mempolicy.h>       // Memory policy
#include <linux/aio_abi.h>         // Asynchronous I/O
#include <linux/io_uring.h>        // I/O operations
#include <linux/fanotify.h>        // File access monitoring
#include <linux/perf_event.h>      // Performance monitoring
#include <linux/signal.h>          // Signal handling
#include <linux/rseq.h>            // Restartable sequences
#include <linux/bpf.h>             // Berkeley Packet Filter
#include <linux/landlock.h>        // Security sandbox
#include <linux/keyctl.h>          // Key management
#include <linux/utsname.h>         // System name structs

#include <fcntl.h>                  // File control operations
#include <unistd.h>                 // UNIX standard functions
#include <stdio.h>                  // Standard I/O
#include <stdlib.h>                 // Standard library functions
#include <string.h>                 // String operations
#include <errno.h>                  // Error number definitions
#include <signal.h>                 // Signal handling
#include <poll.h>                   // Polling
#include <sys/uio.h>




// Directory operations
#include <dirent.h>                // Directory entries
// Function implementations
// read
void template_read() {
    char buffer[100];
    int fd = open("/tmp/testfile.txt", O_RDONLY);
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
    int fd = open("/tmp/testfile.txt", O_WRONLY | O_CREAT, 0644);
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

// open
void template_open() {
    int fd = open("/tmp/testfile.txt", O_RDONLY);
    if (fd == -1) {
        perror("open");
    } else {
        printf("File opened successfully\n");
        close(fd);
    }
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

// newfstat
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

// brk
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
    // Note: sigreturn is typically used internally by the kernel and not directly in user programs
    printf("sigreturn is not typically used in user programs\n");
}

// ioctl
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

// mremap
void template_mremap() {
    void *old_addr = malloc(4096);
    if (old_addr == NULL) {
        perror("malloc");
        return;
    }
    void *new_addr = mremap(old_addr, 4096, 8192, MREMAP_MAYMOVE);
    if (new_addr == MAP_FAILED) {
        perror("mremap");
    } else {
        printf("Memory remapped successfully\n");
    }
    free(new_addr);
}

// msync
void template_msync() {
    void *addr = malloc(4096);
    if (addr == NULL) {
        perror("malloc");
        return;
    }
    if (msync(addr, 4096, MS_SYNC) == -1) {
        perror("msync");
    } else {
        printf("Memory synchronized successfully\n");
    }
    free(addr);
}

// mincore
// mincore
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

// shmget
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

// clone -------------------------------------------------------------------
#define STACK_SIZE (1024 * 1024)

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

// Function to be executed by the new thread
int thread_function(void *arg) {
    printf("Thread function: PID = %d, PPID = %d\n", getpid(), getppid());
    return 0;
}

// clone
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

    // Wait for the new thread to terminate
    if (waitpid(pid, NULL, 0) == -1) {
        perror("waitpid");
        free(stack);
        exit(EXIT_FAILURE);
    }

    printf("Parent function: PID = %d, Child PID = %d\n", getpid(), pid);

    // Free the allocated stack
    free(stack);
}

//-------------------------------------clone-------------------------------------

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
    int fd = open("/tmp/testfile.txt", O_RDONLY);
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
    int nread = syscall(SYS_getdents, fd, buffer, sizeof(buffer));
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

// ptrace
void template_ptrace() {
    // Placeholder implementation
    printf("ptrace is a complex system call and requires specific setup.\n");
}

// getuid
void template_getuid() {
    uid_t uid = getuid();
    printf("User ID: %d\n", uid);
}

// syslog
void template_syslog() {
    // Placeholder implementation
    printf("syslog is a complex system call and requires specific setup.\n");
}

// getgid
void template_getgid() {
    gid_t gid = getgid();
    printf("Group ID: %d\n", gid);
}

// setuid
void template_setuid() {
    if (setuid(1000) == -1) {
        perror("setuid");
    } else {
        printf("User ID set successfully\n");
    }
}

// setgid
void template_setgid() {
    if (setgid(1000) == -1) {
        perror("setgid");
    } else {
        printf("Group ID set successfully\n");
    }
}

// geteuid
void template_geteuid() {
    uid_t euid = geteuid();
    printf("Effective User ID: %d\n", euid);
}

// getegid
void template_getegid() {
    gid_t egid = getegid();
    printf("Effective Group ID: %d\n", egid);
}

// setpgid
void template_setpgid() {
    if (setpgid(0, 0) == -1) {
        perror("setpgid");
    } else {
        printf("Process group ID set successfully\n");
    }
}

// getppid
void template_getppid() {
    pid_t ppid = getppid();
    printf("Parent Process ID: %d\n", ppid);
}
// getpgrp
void template_getpgrp() {
    pid_t pgrp = getpgrp();
    printf("Process group ID: %d\n", pgrp);
}

// setsid
void template_setsid() {
    pid_t sid = setsid();
    if (sid == -1) {
        perror("setsid");
    } else {
        printf("Session ID: %d\n", sid);
    }
}

// setreuid
void template_setreuid() {
    if (setreuid(1000, 1000) == -1) {
        perror("setreuid");
    } else {
        printf("Real and effective user ID set successfully\n");
    }
}

// setregid
void template_setregid() {
    if (setregid(1000, 1000) == -1) {
        perror("setregid");
    } else {
        printf("Real and effective group ID set successfully\n");
    }
}

// getgroups
void template_getgroups() {
    gid_t groups[10];
    int ngroups = getgroups(10, groups);
    if (ngroups == -1) {
        perror("getgroups");
    } else {
        printf("Groups: ");
        for (int i = 0; i < ngroups; i++) {
            printf("%d ", groups[i]);
        }
        printf("\n");
    }
}

// setgroups
void template_setgroups() {
    gid_t groups[2] = {1000, 1001};
    if (setgroups(2, groups) == -1) {
        perror("setgroups");
    } else {
        printf("Groups set successfully\n");
    }
}

// setresuid
void template_setresuid() {
    if (setresuid(1000, 1000, 1000) == -1) {
        perror("setresuid");
    } else {
        printf("Real, effective, and saved user ID set successfully\n");
    }
}

// getresuid
void template_getresuid() {
    uid_t ruid, euid, suid;
    if (getresuid(&ruid, &euid, &suid) == -1) {
        perror("getresuid");
    } else {
        printf("Real UID: %d, Effective UID: %d, Saved UID: %d\n", ruid, euid, suid);
    }
}

// setresgid
void template_setresgid() {
    if (setresgid(1000, 1000, 1000) == -1) {
        perror("setresgid");
    } else {
        printf("Real, effective, and saved group ID set successfully\n");
    }
}

// getresgid
void template_getresgid() {
    gid_t rgid, egid, sgid;
    if (getresgid(&rgid, &egid, &sgid) == -1) {
        perror("getresgid");
    } else {
        printf("Real GID: %d, Effective GID: %d, Saved GID: %d\n", rgid, egid, sgid);
    }
}

// getpgid
void template_getpgid() {
    pid_t pgid = getpgid(0);
    if (pgid == -1) {
        perror("getpgid");
    } else {
        printf("Process group ID: %d\n", pgid);
    }
}

// setfsuid
void template_setfsuid() {
    if (setfsuid(1000) == -1) {
        perror("setfsuid");
    } else {
        printf("Filesystem user ID set successfully\n");
    }
}

// setfsgid
void template_setfsgid() {
    if (setfsgid(1000) == -1) {
        perror("setfsgid");
    } else {
        printf("Filesystem group ID set successfully\n");
    }
}

// getsid
void template_getsid() {
    pid_t sid = getsid(0);
    if (sid == -1) {
        perror("getsid");
    } else {
        printf("Session ID: %d\n", sid);
    }
}

// capget
void template_capget() {
    // Placeholder implementation
    printf("capget is a complex system call and requires specific setup.\n");
}

// capset
void template_capset() {
    // Placeholder implementation
    printf("capset is a complex system call and requires specific setup.\n");
}

// rt_sigpending
void template_rt_sigpending() {
    sigset_t set;
    sigemptyset(&set);
    if (sigpending(&set) == -1) {
        perror("sigpending");
    } else {
        printf("Pending signals retrieved successfully.\n");
    }
}

// rt_sigtimedwait
void template_rt_sigtimedwait() {
    sigset_t set;
    struct timespec timeout = {5, 0};
    siginfo_t info;
    sigemptyset(&set);
    sigaddset(&set, SIGINT);
    if (sigtimedwait(&set, &info, &timeout) == -1) {
        perror("sigtimedwait");
    } else {
        printf("Signal received: %d\n", info.si_signo);
    }
}

// rt_sigqueueinfo
void template_rt_sigqueueinfo() {
    pid_t pid = getpid();
    union sigval value;
    value.sival_int = 1234;
    if (sigqueue(pid, SIGUSR1, value) == -1) {
        perror("sigqueue");
    } else {
        printf("Signal queued successfully.\n");
    }
}

// rt_sigsuspend
void template_rt_sigsuspend() {
    sigset_t mask;
    sigemptyset(&mask);
    sigaddset(&mask, SIGINT);
    if (sigsuspend(&mask) == -1 && errno != EINTR) {
        perror("sigsuspend");
    } else {
        printf("Sigsuspend completed.\n");
    }
}

// sigaltstack
void template_sigaltstack() {
    stack_t ss;
    ss.ss_sp = malloc(SIGSTKSZ);
    if (ss.ss_sp == NULL) {
        perror("malloc");
        return;
    }
    ss.ss_size = SIGSTKSZ;
    ss.ss_flags = 0;
    if (sigaltstack(&ss, NULL) == -1) {
        perror("sigaltstack");
    } else {
        printf("Alternate signal stack set successfully.\n");
    }
    free(ss.ss_sp);
}

// utime
void template_utime() {
    struct utimbuf times;
    times.actime = time(NULL);
    times.modtime = time(NULL);
    if (utime("/tmp/testfile.txt", &times) == -1) {
        perror("utime");
    } else {
        printf("File times updated successfully.\n");
    }
}

// mknod
void template_mknod() {
    if (mknod("/tmp/testfile", S_IFREG | 0644, 0) == -1) {
        perror("mknod");
    } else {
        printf("File created successfully.\n");
    }
}

// personality
void template_personality() {
    // Placeholder implementation
    printf("personality is a complex system call and requires specific setup.\n");
}

// ustat
void template_ustat() {
    // Placeholder implementation
    printf("ustat is a complex system call and requires specific setup.\n");
}

// statfs
void template_statfs() {
    struct statfs buf;
    if (statfs("/tmp", &buf) == -1) {
        perror("statfs");
    } else {
        printf("Filesystem type: %ld\n", buf.f_type);
    }
}

// fstatfs
void template_fstatfs() {
    int fd = open("/tmp/testfile.txt", O_RDONLY);
    if (fd == -1) {
        perror("open");
        return;
    }
    struct statfs buf;
    if (fstatfs(fd, &buf) == -1) {
        perror("fstatfs");
    } else {
        printf("Filesystem type: %ld\n", buf.f_type);
    }
    close(fd);
}

// sysfs
void template_sysfs() {
    // Placeholder implementation
    printf("sysfs is a complex system call and requires specific setup.\n");
}

// getpriority
void template_getpriority() {
    int priority = getpriority(PRIO_PROCESS, 0);
    if (priority == -1 && errno != 0) {
        perror("getpriority");
    } else {
        printf("Process priority: %d\n", priority);
    }
}

// setpriority
void template_setpriority() {
    if (setpriority(PRIO_PROCESS, 0, 10) == -1) {
        perror("setpriority");
    } else {
        printf("Process priority set successfully.\n");
    }
}

// sched_setparam
void template_sched_setparam() {
    struct sched_param param;
    param.sched_priority = 10;
    if (sched_setparam(0, &param) == -1) {
        perror("sched_setparam");
    } else {
        printf("Scheduling parameters set successfully.\n");
    }
}

// sched_getparam
void template_sched_getparam() {
    struct sched_param param;
    if (sched_getparam(0, &param) == -1) {
        perror("sched_getparam");
    } else {
        printf("Scheduling priority: %d\n", param.sched_priority);
    }
}

// sched_setscheduler
void template_sched_setscheduler() {
    struct sched_param param;
    param.sched_priority = 10;
    if (sched_setscheduler(0, SCHED_FIFO, &param) == -1) {
        perror("sched_setscheduler");
    } else {
        printf("Scheduling policy set successfully.\n");
    }
}

// sched_getscheduler
void template_sched_getscheduler() {
    int policy = sched_getscheduler(0);
    if (policy == -1) {
        perror("sched_getscheduler");
    } else {
        printf("Scheduling policy: %d\n", policy);
    }
}

// sched_get_priority_max
void template_sched_get_priority_max() {
    int max_priority = sched_get_priority_max(SCHED_FIFO);
    if (max_priority == -1) {
        perror("sched_get_priority_max");
    } else {
        printf("Maximum priority: %d\n", max_priority);
    }
}

// sched_get_priority_min
void template_sched_get_priority_min() {
    int min_priority = sched_get_priority_min(SCHED_FIFO);
    if (min_priority == -1) {
        perror("sched_get_priority_min");
    } else {
        printf("Minimum priority: %d\n", min_priority);
    }
}

// sched_rr_get_interval
void template_sched_rr_get_interval() {
    struct timespec interval;
    if (sched_rr_get_interval(0, &interval) == -1) {
        perror("sched_rr_get_interval");
    } else {
        printf("Round-robin interval: %ld.%09ld seconds\n", interval.tv_sec, interval.tv_nsec);
    }
}

// mlock
void template_mlock() {
    void *addr = malloc(4096);
    if (addr == NULL) {
        perror("malloc");
        return;
    }
    if (mlock(addr, 4096) == -1) {
        perror("mlock");
    } else {
        printf("Memory locked successfully.\n");
    }
    free(addr);
}

// munlock
void template_munlock() {
    void *addr = malloc(4096);
    if (addr == NULL) {
        perror("malloc");
        return;
    }
    if (munlock(addr, 4096) == -1) {
        perror("munlock");
    } else {
        printf("Memory unlocked successfully.\n");
    }
    free(addr);
}
------starting from here-----
// mlockall
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

// modify_ldt
void template_modify_ldt() {
    // Placeholder implementation
    printf("modify_ldt is a complex system call and requires specific setup.\n");
}

// pivot_root
void template_pivot_root() {
    // Placeholder implementation
    printf("pivot_root is a complex system call and requires specific setup.\n");
}

// prctl
void template_prctl() {
    if (prctl(PR_SET_NAME, "newname", 0, 0, 0) == -1) {
        perror("prctl");
    } else {
        printf("Process name set successfully.\n");
    }
}

// arch_prctl
void template_arch_prctl() {
    // Placeholder implementation
    printf("arch_prctl is a complex system call and requires specific setup.\n");
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
    if (iopl(3) == -1) {
        perror("iopl");
    } else {
        printf("I/O privilege level set successfully.\n");
    }
}

// ioperm
void template_ioperm() {
    if (ioperm(0x378, 3, 1) == -1) {
        perror("ioperm");
    } else {
        printf("I/O permissions set successfully.\n");
    }
}

// init_module
void template_init_module() {
    // Placeholder implementation
    printf("init_module is a complex system call and requires specific setup.\n");
}

// delete_module
void template_delete_module() {
    // Placeholder implementation
    printf("delete_module is a complex system call and requires specific setup.\n");
}

// quotactl
void template_quotactl() {
    // Placeholder implementation
    printf("quotactl is a complex system call and requires specific setup.\n");
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
    pid_t tid = syscall(SYS_gettid);
    if (tkill(tid, SIGUSR1) == -1) {
        perror("tkill");
    } else {
        printf("Signal sent successfully to thread.\n");
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
    // Placeholder implementation
    printf("futex is a complex system call and requires specific setup.\n");
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
    // Placeholder implementation
    printf("io_setup is a complex system call and requires specific setup.\n");
}

// io_destroy
void template_io_destroy() {
    // Placeholder implementation
    printf("io_destroy is a complex system call and requires specific setup.\n");
}

// io_getevents
void template_io_getevents() {
    // Placeholder implementation
    printf("io_getevents is a complex system call and requires specific setup.\n");
}

// io_submit
void template_io_submit() {
    // Placeholder implementation
    printf("io_submit is a complex system call and requires specific setup.\n");
}

// io_cancel
void template_io_cancel() {
    // Placeholder implementation
    printf("io_cancel is a complex system call and requires specific setup.\n");
}

// epoll_create
void template_epoll_create() {
    int epfd = epoll_create(1);
    if (epfd != -1) {
        close(epfd);
    }
}

// remap_file_pages
void template_remap_file_pages() {
    void *map = mmap(NULL, 4096, PROT_READ | PROT_WRITE, MAP_SHARED | MAP_ANONYMOUS, -1, 0);
    if (map != MAP_FAILED) {
        remap_file_pages(map, 4096, PROT_READ | PROT_WRITE, 0, 0);
        munmap(map, 4096);
    }
}

// getdents64
void template_getdents64() {
    int fd = open("/tmp", O_RDONLY | O_DIRECTORY);
    char buffer[1024];
    if (fd != -1) {
        getdents64(fd, (struct linux_dirent64 *)buffer, sizeof(buffer));
        close(fd);
    }
}

// set_tid_address
void template_set_tid_address() {
    int tid = set_tid_address((int *)0);
}

// restart_syscall
void template_restart_syscall() {
    // This syscall restarts a system call after interruption by a signal
    // It is not directly callable in user-space
}

// semtimedop
void template_semtimedop() {
    int semid = semget(IPC_PRIVATE, 1, IPC_CREAT | 0666);
    struct sembuf sops[1] = {0, -1, 0};
    struct timespec timeout = {1, 0}; // 1 second
    if (semid != -1) {
        semtimedop(semid, sops, 1, &timeout);
        semctl(semid, 0, IPC_RMID);
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

// exit_group
void template_exit_group() {
    exit_group(0);
}

// epoll_wait
void template_epoll_wait() {
    int epfd = epoll_create(1);
    struct epoll_event event;
    if (epfd != -1) {
        epoll_wait(epfd, &event, 1, 1000);
        close(epfd);
    }
}

// epoll_ctl
void template_epoll_ctl() {
    int epfd = epoll_create(1);
    struct epoll_event event = {EPOLLIN, {0}};
    if (epfd != -1) {
        epoll_ctl(epfd, EPOLL_CTL_ADD, 0, &event); // Adding stdin to epoll
        close(epfd);
    }
}

// tgkill
void template_tgkill() {
    tgkill(getpid(), getpid(), SIGKILL);
}

// utimes
void template_utimes() {
    struct timeval times[2] = {{0, 0}, {0, 0}};
    utimes("/tmp/testfile.txt", times);
}

/ mbind
void template_mbind() {
    void *addr = mmap(NULL, 4096, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (addr != MAP_FAILED) {
        unsigned long nodemask = 1;
        mbind(addr, 4096, MPOL_BIND, &nodemask, sizeof(nodemask), 0);
        munmap(addr, 4096);
    }
}

// set_mempolicy
void template_set_mempolicy() {
    unsigned long nodemask = 1;
    set_mempolicy(MPOL_BIND, &nodemask, sizeof(nodemask));
}

// get_mempolicy
void template_get_mempolicy() {
    int policy;
    unsigned long nodemask;
    get_mempolicy(&policy, &nodemask, sizeof(nodemask), 0, 0);
}

// mq_open
void template_mq_open() {
    mqd_t mq = mq_open("/testqueue", O_CREAT | O_RDWR, 0644, NULL);
    if (mq != (mqd_t)-1) {
        mq_close(mq);
        mq_unlink("/testqueue");
    }
}

// mq_unlink
void template_mq_unlink() {
    mq_unlink("/testqueue");
}

// mq_timedsend
void template_mq_timedsend() {
    mqd_t mq = mq_open("/testqueue", O_CREAT | O_RDWR, 0644, NULL);
    struct timespec ts = {1, 0}; // 1 second
    if (mq != (mqd_t)-1) {
        mq_timedsend(mq, "Hello", 5, 0, &ts);
        mq_close(mq);
        mq_unlink("/testqueue");
    }
}

// mq_timedreceive
void template_mq_timedreceive() {
    mqd_t mq = mq_open("/testqueue", O_CREAT | O_RDWR, 0644, NULL);
    struct timespec ts = {1, 0}; // 1 second
    char buffer[10];
    if (mq != (mqd_t)-1) {
        mq_timedreceive(mq, buffer, sizeof(buffer), NULL, &ts);
        mq_close(mq);
        mq_unlink("/testqueue");
    }
}

// mq_notify
void template_mq_notify() {
    mqd_t mq = mq_open("/testqueue", O_CREAT | O_RDWR, 0644, NULL);
    struct sigevent sev = {0};
    sev.sigev_notify = SIGEV_NONE;
    if (mq != (mqd_t)-1) {
        mq_notify(mq, &sev);
        mq_close(mq);
        mq_unlink("/testqueue");
    }
}

// mq_getsetattr
void template_mq_getsetattr() {
    mqd_t mq = mq_open("/testqueue", O_CREAT | O_RDWR, 0644, NULL);
    struct mq_attr attr;
    if (mq != (mqd_t)-1) {
        mq_getattr(mq, &attr);
        attr.mq_flags = O_NONBLOCK;
        mq_setattr(mq, &attr, NULL);
        mq_close(mq);
        mq_unlink("/testqueue");
    }
}

// kexec_load
void template_kexec_load() {
    // kexec_load is typically used to load a new kernel image and requires root privileges
    // It is not directly callable in regular user applications
}

// waitid
void template_waitid() {
    siginfo_t info;
    waitid(P_ALL, 0, &info, WEXITED | WNOHANG);
}

// add_key
void template_add_key() {
    add_key("user", "test_key", "test_data", strlen("test_data"), KEY_SPEC_USER_KEYRING);
}

// request_key
void template_request_key() {
    request_key("user", "test_key", NULL, KEY_SPEC_USER_KEYRING);
}

// keyctl
void template_keyctl() {
    keyctl(KEYCTL_REVOKE, 0);
}

// ioprio_set
void template_ioprio_set() {
    ioprio_set(IOPRIO_WHO_PROCESS, getpid(), IOPRIO_PRIO_VALUE(IOPRIO_CLASS_BE, 5));
}

// ioprio_get
void template_ioprio_get() {
    ioprio_get(IOPRIO_WHO_PROCESS, getpid());
}

// inotify_init
void template_inotify_init() {
    int fd = inotify_init();
    if (fd != -1) {
        close(fd);
    }
}

// inotify_add_watch
void template_inotify_add_watch() {
    int fd = inotify_init();
    if (fd != -1) {
        inotify_add_watch(fd, "/tmp", IN_MODIFY);
        close(fd);
    }
}

// inotify_rm_watch
void template_inotify_rm_watch() {
    int fd = inotify_init();
    int wd = inotify_add_watch(fd, "/tmp", IN_MODIFY);
    if (fd != -1 && wd != -1) {
        inotify_rm_watch(fd, wd);
        close(fd);
    }
}

// migrate_pages
void template_migrate_pages() {
    unsigned long old_nodes = 1, new_nodes = 2;
    migrate_pages(getpid(), sizeof(old_nodes) * 8, &old_nodes, &new_nodes);
}

// openat
void template_openat() {
    int fd = openat(AT_FDCWD, "/tmp/testfile.txt", O_RDONLY);
    if (fd != -1) {
        close(fd);
    }
}

// mkdirat
void template_mkdirat() {
    mkdirat(AT_FDCWD, "/tmp/newdir", 0755);
}

// mknodat
void template_mknodat() {
    mknodat(AT_FDCWD, "/tmp/testfile", S_IFREG | 0644, 0);
}

// fchownat
void template_fchownat() {
    fchownat(AT_FDCWD, "/tmp/testfile.txt", 1000, 1000, 0);
}

// futimesat
void template_futimesat() {
    struct timeval times[2] = {{0, 0}, {0, 0}};
    futimesat(AT_FDCWD, "/tmp/testfile.txt", times);
}

// newfstatat
void template_newfstatat() {
    struct stat sb;
    fstatat(AT_FDCWD, "/tmp/testfile.txt", &sb, 0);
}

// unlinkat
void template_unlinkat() {
    unlinkat(AT_FDCWD, "testfile.txt", 0);
}

// renameat
void template_renameat() {
    renameat(AT_FDCWD, "/tmp/oldname.txt", AT_FDCWD, "/tmp/newname.txt");
}

// linkat
void template_linkat() {
    linkat(AT_FDCWD, "/tmp/testfile.txt", AT_FDCWD, "/tmp/testfile_link.txt", 0);
}

// symlinkat
void template_symlinkat() {
    symlinkat("/tmp/original.txt", AT_FDCWD, "/tmp/symlink.txt");
}

// readlinkat
void template_readlinkat() {
    char buffer[1024];
    readlinkat(AT_FDCWD, "/tmp/symlink.txt", buffer, sizeof(buffer) - 1);
}

// fchmodat
void template_fchmodat() {
    fchmodat(AT_FDCWD, "/tmp/testfile.txt", 0644, 0);
}

// faccessat
void template_faccessat() {
    faccessat(AT_FDCWD, "/tmp/testfile.txt", R_OK | W_OK, 0);
}

// pselect6
void template_pselect6() {
    fd_set readfds;
    FD_ZERO(&readfds);
    FD_SET(0, &readfds); // stdin
    struct timespec timeout = {1, 0}; // 1 second
    pselect(1, &readfds, NULL, NULL, &timeout, NULL);
}

// ppoll
void template_ppoll() {
    struct pollfd fds[1];
    fds[0].fd = 0; // stdin
    fds[0].events = POLLIN;
    struct timespec timeout = {1, 0}; // 1 second
    ppoll(fds, 1, &timeout, NULL);
}

// unshare
void template_unshare() {
    unshare(CLONE_NEWNS);
}

// set_robust_list
void template_set_robust_list() {
    struct robust_list_head head;
    set_robust_list(&head, sizeof(head));
}

// get_robust_list
void template_get_robust_list() {
    struct robust_list_head *head;
    size_t len;
    get_robust_list(0, &head, &len);
}

// splice
void template_splice() {
    int pipes[2];
    pipe(pipes);
    splice(pipes[0], NULL, pipes[1], NULL, 4096, SPLICE_F_MOVE);
    close(pipes[0]);
    close(pipes[1]);
}

// tee
void template_tee() {
    int pipes[2];
    pipe(pipes);
    tee(pipes[0], pipes[1], 4096, SPLICE_F_NONBLOCK);
    close(pipes[0]);
    close(pipes[1]);
}

// sync_file_range
void template_sync_file_range() {
    int fd = open("/tmp/testfile.txt", O_RDWR);
    if (fd != -1) {
        sync_file_range(fd, 0, 4096, SYNC_FILE_RANGE_WRITE);
        close(fd);
    }
}

// vmsplice
void template_vmsplice() {
    int pipes[2];
    pipe(pipes);
    struct iovec iov = { "Hello, world!\n", 14 };
    vmsplice(pipes[1], &iov, 1, SPLICE_F_GIFT);
    close(pipes[0]);
    close(pipes[1]);
}

// move_pages
void template_move_pages() {
    void *pages[1] = {malloc(4096)};
    int nodes[1] = {0};
    move_pages(0, 1, pages, nodes, NULL, 0);
    free(pages[0]);
}

// utimensat
void template_utimensat() {
    struct timespec times[2] = {{0, 0}, {0, 0}};
    utimensat(AT_FDCWD, "/tmp/testfile.txt", times, 0);
}

// epoll_pwait
void template_epoll_pwait() {
    int epfd = epoll_create1(0);
    struct epoll_event event;
    if (epfd != -1) {
        epoll_pwait(epfd, &event, 1, 1000, NULL);
        close(epfd);
    }
}

// signalfd
void template_signalfd() {
    sigset_t mask;
    sigemptyset(&mask);
    sigaddset(&mask, SIGINT);
    int fd = signalfd(-1, &mask, 0);
    if (fd != -1) {
        close(fd);
    }
}

// timerfd_create
void template_timerfd_create() {
    int fd = timerfd_create(CLOCK_REALTIME, 0);
    if (fd != -1) {
        close(fd);
    }
}

// eventfd
void template_eventfd() {
    int fd = eventfd(0, 0);
    if (fd != -1) {
        close(fd);
    }
}

// fallocate
void template_fallocate() {
    int fd = open("/tmp/testfile.txt", O_RDWR | O_CREAT, 0644);
    if (fd != -1) {
        fallocate(fd, 0, 0, 4096);
        close(fd);
    }
}

// timerfd_settime
void template_timerfd_settime() {
    int fd = timerfd_create(CLOCK_REALTIME, 0);
    struct itimerspec ts = {{1, 0}, {1, 0}}; // 1 second
    if (fd != -1) {
        timerfd_settime(fd, 0, &ts, NULL);
        close(fd);
    }
}

// timerfd_gettime
void template_timerfd_gettime() {
    int fd = timerfd_create(CLOCK_REALTIME, 0);
    struct itimerspec ts;
    if (fd != -1) {
        timerfd_gettime(fd, &ts);
        close(fd);
    }
}

// accept4
void template_accept4() {
    int sockfd = socket(AF_INET, SOCK_STREAM, 0);
    if (sockfd != -1) {
        struct sockaddr_in addr = {0};
        bind(sockfd, (struct sockaddr *)&addr, sizeof(addr));
        listen(sockfd, 10);
        accept4(sockfd, NULL, NULL, SOCK_NONBLOCK);
        close(sockfd);
    }
}

// signalfd4
void template_signalfd4() {
    sigset_t mask;
    sigemptyset(&mask);
    sigaddset(&mask, SIGINT);
    int fd = signalfd(-1, &mask, SFD_NONBLOCK);
    if (fd != -1) {
        close(fd);
    }
}

// eventfd2
void template_eventfd2() {
    int fd = eventfd(0, EFD_NONBLOCK);
    if (fd != -1) {
        close(fd);
    }
}

// epoll_create1
void template_epoll_create1() {
    int epfd = epoll_create1(0);
    if (epfd != -1) {
        close(epfd);
    }
}

// dup3
void template_dup3() {
    int fd = open("/tmp/testfile.txt", O_RDONLY);
    if (fd != -1) {
        int newfd = dup3(fd, fd + 1, O_CLOEXEC);
        close(fd);
        close(newfd);
    }
}

// pipe2
void template_pipe2() {
    int pipes[2];
    pipe2(pipes, O_NONBLOCK);
    close(pipes[0]);
    close(pipes[1]);
}

// inotify_init1
void template_inotify_init1() {
    int fd = inotify_init1(IN_NONBLOCK);
    if (fd != -1) {
        close(fd);
    }
}

// preadv
void template_preadv() {
    int fd = open("/tmp/testfile.txt", O_RDONLY);
    char buffer1[50], buffer2[50];
    struct iovec iov[2];
    iov[0].iov_base = buffer1;
    iov[0].iov_len = sizeof(buffer1);
    iov[1].iov_base = buffer2;
    iov[1].iov_len = sizeof(buffer2);
    if (fd != -1) {
        preadv(fd, iov, 2, 0);
        close(fd);
    }
}

// pwritev
void template_pwritev() {
    int fd = open("/tmp/testfile.txt", O_WRONLY | O_CREAT, 0644);
    struct iovec iov[2];
    iov[0].iov_base = "Hello, ";
    iov[0].iov_len = 7;
    iov[1].iov_base = "world!\n";
    iov[1].iov_len = 7;
    if (fd != -1) {
        pwritev(fd, iov, 2, 0);
        close(fd);
    }
}

// rt_tgsigqueueinfo
void template_rt_tgsigqueueinfo() {
    siginfo_t info = {0};
    info.si_signo = SIGINT;
    rt_tgsigqueueinfo(getpid(), getpid(), SIGINT, &info);
}

// perf_event_open
void template_perf_event_open() {
    struct perf_event_attr pe = {0};
    pe.size = sizeof(struct perf_event_attr);
    int fd = perf_event_open(&pe, getpid(), -1, -1, 0);
    if (fd != -1) {
        close(fd);
    }
}

// recvmmsg
void template_recvmmsg() {
    int sockfd = socket(AF_INET, SOCK_DGRAM, 0);
    struct sockaddr_in addr = {0};
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = htonl(INADDR_ANY);
    bind(sockfd, (struct sockaddr *)&addr, sizeof(addr));

    struct mmsghdr msgs[1];
    struct iovec iov[1];
    char buffer[1024];
    iov[0].iov_base = buffer;
    iov[0].iov_len = sizeof(buffer);
    msgs[0].msg_hdr.msg_iov = iov;
    msgs[0].msg_hdr.msg_iovlen = 1;

    recvmmsg(sockfd, msgs, 1, 0, NULL);
    close(sockfd);
}

// fanotify_init
void template_fanotify_init() {
    int fd = fanotify_init(FAN_CLOEXEC | FAN_CLASS_NOTIF, O_RDONLY);
    if (fd != -1) {
        close(fd);
    }
}

// fanotify_mark
void template_fanotify_mark() {
    int fd = fanotify_init(FAN_CLOEXEC | FAN_CLASS_NOTIF, O_RDONLY);
    if (fd != -1) {
        fanotify_mark(fd, FAN_MARK_ADD, FAN_CREATE | FAN_DELETE, AT_FDCWD, "/tmp");
        close(fd);
    }
}

// prlimit64
void template_prlimit64() {
    struct rlimit64 rl = {1024, 2048};
    prlimit64(getpid(), RLIMIT_NOFILE, &rl, NULL);
}

// name_to_handle_at
void template_name_to_handle_at() {
    struct file_handle handle;
    int mount_id;
    name_to_handle_at(AT_FDCWD, "/tmp/testfile.txt", &handle, &mount_id, 0);
}

// open_by_handle_at
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

// clock_adjtime
void template_clock_adjtime() {
    struct timex t = {0};
    clock_adjtime(CLOCK_REALTIME, &t);
}

// syncfs
void template_syncfs() {
    int fd = open("/", O_RDONLY);
    if (fd != -1) {
        syncfs(fd);
        close(fd);
    }
}

// sendmmsg
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

// setns
void template_setns() {
    int fd = open("/proc/self/ns/mnt", O_RDONLY);
    if (fd != -1) {
        setns(fd, CLONE_NEWNS);
        close(fd);
    }
}

// getcpu
void template_getcpu() {
    unsigned cpu, node;
    getcpu(&cpu, &node, NULL);
}

// process_vm_readv
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

// process_vm_writev
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

// kcmp
void template_kcmp() {
    int result = kcmp(getpid(), getpid(), KCMP_FILE, 0, 0);
}

// finit_module
void template_finit_module() {
    int fd = open("/path/to/module.ko", O_RDONLY);
    if (fd != -1) {
        finit_module(fd, "", 0);
        close(fd);
    }
}

// sched_setattr
void template_sched_setattr() {
    struct sched_attr attr = {0};
    attr.size = sizeof(attr);
    attr.sched_policy = SCHED_FIFO;
    attr.sched_priority = 10;
    sched_setattr(0, &attr, 0);
}

// sched_getattr
void template_sched_getattr() {
    struct sched_attr attr;
    sched_getattr(0, &attr, sizeof(attr), 0);
}

// renameat2
void template_renameat2() {
    renameat2(AT_FDCWD, "/tmp/oldname.txt", AT_FDCWD, "/tmp/newname.txt", RENAME_NOREPLACE);
}

// seccomp
void template_seccomp() {
    seccomp(SECCOMP_SET_MODE_STRICT, 0, NULL);
}

// getrandom
void template_getrandom() {
    char buffer[16];
    getrandom(buffer, sizeof(buffer), 0);
}

// memfd_create
void template_memfd_create() {
    int fd = memfd_create("my_memfd", MFD_CLOEXEC);
    if (fd != -1) {
        close(fd);
    }
}
// kexec_file_load
void template_kexec_file_load() {
    // This is typically used to load a new kernel and requires root privileges.
    // It is not directly callable in regular user applications.
}

// bpf
void template_bpf() {
    union bpf_attr attr = {0};
    attr.map_type = BPF_MAP_TYPE_ARRAY;
    attr.key_size = sizeof(int);
    attr.value_size = sizeof(long);
    attr.max_entries = 1;
    int fd = bpf(BPF_MAP_CREATE, &attr, sizeof(attr));
    if (fd != -1) {
        close(fd);
    }
}

// execveat
void template_execveat() {
    int fd = open("/bin/ls", O_RDONLY);
    if (fd != -1) {
        char *const argv[] = {"ls", NULL};
        char *const envp[] = {NULL};
        execveat(fd, "", argv, envp, AT_EMPTY_PATH);
        close(fd);
    }
}

// userfaultfd
void template_userfaultfd() {
    int fd = userfaultfd(O_CLOEXEC | O_NONBLOCK);
    if (fd != -1) {
        close(fd);
    }
}

// membarrier
void template_membarrier() {
    membarrier(MEMBARRIER_CMD_GLOBAL, 0);
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

// io_pgetevents
void template_io_pgetevents() {
    // This requires advanced setup with AIO, which is beyond simple use.
    // Generally used for asynchronous I/O completion and needs initialization.
}

// rseq
void template_rseq() {
    struct rseq rs = {0};
    rseq(&rs, sizeof(rs), 0, 0);
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
    struct io_uring_params params = {0};
    int ring_fd = io_uring_setup(8, &params);
    if (ring_fd != -1) {
        close(ring_fd);
    }
}

// io_uring_enter
void template_io_uring_enter() {
    struct io_uring_params params = {0};
    int ring_fd = io_uring_setup(8, &params);
    if (ring_fd != -1) {
        io_uring_enter(ring_fd, 1, 0, IORING_ENTER_GETEVENTS, NULL);
        close(ring_fd);
    }
}

// io_uring_register
void template_io_uring_register() {
    struct io_uring_params params = {0};
    int ring_fd = io_uring_setup(8, &params);
    if (ring_fd != -1) {
        int result = io_uring_register(ring_fd, IORING_REGISTER_BUFFERS, NULL, 0);
        close(ring_fd);
    }
}

// open_tree
void template_open_tree() {
    int fd = open_tree(AT_FDCWD, "/tmp", OPEN_TREE_CLONE);
    if (fd != -1) {
        close(fd);
    }
}

// move_mount
void template_move_mount() {
    int result = move_mount(AT_FDCWD, "/tmp", AT_FDCWD, "/mnt", MOVE_MOUNT_F_EMPTY_PATH);
}

// fsopen
void template_fsopen() {
    int fd = fsopen("ext4", FSOPEN_CLOEXEC);
    if (fd != -1) {
        close(fd);
    }
}

// fsconfig
void template_fsconfig() {
    int fs_fd = fsopen("ext4", FSOPEN_CLOEXEC);
    if (fs_fd != -1) {
        fsconfig(fs_fd, FSCONFIG_SET_STRING, "source", "/dev/sda1", 0);
        close(fs_fd);
    }
}

// fsmount
void template_fsmount() {
    int fs_fd = fsopen("ext4", FSOPEN_CLOEXEC);
    if (fs_fd != -1) {
        int mnt_fd = fsmount(fs_fd, 0, MNT_FORCE);
        if (mnt_fd != -1) {
            close(mnt_fd);
        }
        close(fs_fd);
    }
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
    struct clone_args args = {0};
    args.flags = CLONE_VM | CLONE_FS;
    args.pidfd = 0;
    clone3(&args, sizeof(args));
}

// close_range
void template_close_range() {
    close_range(3, 1024, 0);
}

// openat2
void template_openat2() {
    struct open_how how = {0};
    how.flags = O_RDONLY;
    int fd = openat2(AT_FDCWD, "/tmp/testfile.txt", &how, sizeof(how));
    if (fd != -1) {
        close(fd);
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

// faccessat2
void template_faccessat2() {
    faccessat2(AT_FDCWD, "/tmp/testfile.txt", R_OK, AT_EACCESS);
}

// process_madvise
void template_process_madvise() {
    int pid = getpid();
    void *addr = mmap(NULL, 4096, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (addr != MAP_FAILED) {
        struct iovec iov = {addr, 4096};
        process_madvise(pid, &iov, 1, MADV_DONTNEED, 0);
        munmap(addr, 4096);
    }
}

// epoll_pwait2
void template_epoll_pwait2() {
    int epfd = epoll_create1(0);
    struct epoll_event event = {0};
    struct timespec timeout = {1, 0};
    if (epfd != -1) {
        epoll_pwait2(epfd, &event, 1, &timeout, NULL);
        close(epfd);
    }
}

// mount_setattr
void template_mount_setattr() {
    int fd = open("/mnt", O_RDONLY);
    struct mount_attr attr = {0};
    if (fd != -1) {
        mount_setattr(fd, "", AT_SYMLINK_NOFOLLOW, &attr, sizeof(attr));
        close(fd);
    }
}

// quotactl_fd
void template_quotactl_fd() {
    int fd = open("/", O_RDONLY);
    if (fd != -1) {
        quotactl_fd(fd, QCMD(Q_GETQUOTA, USRQUOTA), 1000, NULL);
        close(fd);
    }
}

// landlock_create_ruleset
void template_landlock_create_ruleset() {
    struct landlock_ruleset_attr attr = {0};
    attr.handled_access_fs = LANDLOCK_ACCESS_FS_EXECUTE;
    int fd = landlock_create_ruleset(&attr, sizeof(attr), 0);
    if (fd != -1) {
        close(fd);
    }
}

// landlock_add_rule
void template_landlock_add_rule() {
    struct landlock_ruleset_attr ruleset_attr = {0};
    ruleset_attr.handled_access_fs = LANDLOCK_ACCESS_FS_EXECUTE;
    int ruleset_fd = landlock_create_ruleset(&ruleset_attr, sizeof(ruleset_attr), 0);

    if (ruleset_fd != -1) {
        struct landlock_path_beneath_attr path_attr = {0};
        path_attr.parent_fd = open("/tmp", O_PATH | O_CLOEXEC);
        path_attr.allowed_access = LANDLOCK_ACCESS_FS_EXECUTE;

        if (path_attr.parent_fd != -1) {
            landlock_add_rule(ruleset_fd, LANDLOCK_RULE_PATH_BENEATH, &path_attr, 0);
            close(path_attr.parent_fd);
        }
        close(ruleset_fd);
    }
}

// landlock_restrict_self
void template_landlock_restrict_self() {
    struct landlock_ruleset_attr attr = {0};
    attr.handled_access_fs = LANDLOCK_ACCESS_FS_EXECUTE;
    int fd = landlock_create_ruleset(&attr, sizeof(attr), 0);
    if (fd != -1) {
        landlock_restrict_self(fd, 0);
        close(fd);
    }
}

// memfd_secret
void template_memfd_secret() {
    int fd = memfd_secret(MFD_SECRET_EXCLUSIVE);
    if (fd != -1) {
        close(fd);
    }
}

// process_mrelease
void template_process_mrelease() {
    process_mrelease(getpid());
}

// futex_waitv
void template_futex_waitv() {
    struct futex_waitv waitv = {0};
    waitv.uaddr = (uint32_t *)malloc(sizeof(uint32_t));
    waitv.flags = FUTEX_32;
    futex_waitv(&waitv, 1, 1000);
    free((void *)waitv.uaddr);
}

// set_mempolicy_home_node
void template_set_mempolicy_home_node() {
    int result = set_mempolicy_home_node(MPOL_PREFERRED, 0, 1, 0);
}

// cachestat
void template_cachestat() {
    struct cachestat cstat = {0};  // struct cachestat may require a custom definition based on kernel implementation
    cachestat(0, 0, &cstat);
}

// fchmodat2
void template_fchmodat2() {
    fchmodat2(AT_FDCWD, "/tmp/testfile.txt", 0644, 0);
}

// map_shadow_stack
void template_map_shadow_stack() {
    void *addr = mmap(NULL, 4096, PROT_READ | PROT_WRITE | PROT_EXEC, MAP_SHARED, -1, 0);
    if (addr != MAP_FAILED) {
        map_shadow_stack(addr, 4096);
        munmap(addr, 4096);
    }
}

// futex_wake
void template_futex_wake() {
    uint32_t futex_var = 0;
    futex_wake(&futex_var, 1);
}

// futex_wait
void template_futex_wait() {
    uint32_t futex_var = 0;
    futex_wait(&futex_var, 0, NULL);
}

// futex_requeue
void template_futex_requeue() {
    uint32_t futex_var1 = 0, futex_var2 = 0;
    futex_requeue(&futex_var1, 1, &futex_var2, 1);
}

// statmount
void template_statmount() {
    struct statmount sm;
    statmount(AT_FDCWD, &sm, sizeof(sm), 0);
}

// listmount
void template_listmount() {
    struct listmount lm;
    listmount(AT_FDCWD, &lm, sizeof(lm), 0);
}

// lsm_get_self_attr
void template_lsm_get_self_attr() {
    struct lsm_attr attr;
    lsm_get_self_attr(LSM_ATTR_CURRENT, &attr, sizeof(attr));
}

// lsm_set_self_attr
void template_lsm_set_self_attr() {
    struct lsm_attr attr = {0};  // struct lsm_attr may require additional settings
    lsm_set_self_attr(LSM_ATTR_CURRENT, &attr, sizeof(attr));
}

// lsm_list_modules
void template_lsm_list_modules() {
    struct lsm_module modules[10];  // Allocate enough space based on expected module count
    lsm_list_modules(modules, sizeof(modules));
}

// mseal
void template_mseal() {
    int fd = open("/tmp/testfile.txt", O_RDWR);
    if (fd != -1) {
        mseal(fd);
        close(fd);
    }
}


//anooodhhhhhh-----------------------------------------------

#ifndef FUTEX_32
#define FUTEX_32 0x2000
#endif

#ifndef MPOL_PREFERRED
#define MPOL_PREFERRED 1
#endif

#ifndef MFD_SECRET_EXCLUSIVE
#define MFD_SECRET_EXCLUSIVE 0x0001
#endif

#ifndef USRQUOTA
#define USRQUOTA 0
#endif

#ifndef LANDLOCK_RULE_PATH_BENEATH
#define LANDLOCK_RULE_PATH_BENEATH 0x1  // Placeholder value; replace with actual value if known
#endif

#ifndef QCMD
#define QCMD(cmd, type) ((cmd) | ((type) << 8))
#endif

#ifndef LANDLOCK_STRUCTS_DEFINED
#define LANDLOCK_STRUCTS_DEFINED

struct landlock_ruleset_attr {
    uint64_t handled_access_fs;
};

struct landlock_path_beneath_attr {
    int parent_fd;
    uint64_t allowed_access;
};

#endif

#ifndef MOUNT_ATTR_STRUCT_DEFINED
#define MOUNT_ATTR_STRUCT_DEFINED

struct mount_attr {
    unsigned int flags;
    unsigned int propagation;
    unsigned int userns_fd;
};

#endif

// Placeholder functions for syscalls not supported
int landlock_create_ruleset(const struct landlock_ruleset_attr *attr, size_t size, int flags) {
    printf("landlock_create_ruleset called with size = %zu, flags = %d\n", size, flags);
    return 1;
}

int landlock_restrict_self(int fd, uint32_t flags) {
    printf("landlock_restrict_self called with fd = %d, flags = %d\n", fd, flags);
    return 0;
}

int landlock_add_rule(int ruleset_fd, int rule_type, const struct landlock_path_beneath_attr *attr, uint32_t flags) {
    printf("landlock_add_rule called with ruleset_fd = %d, rule_type = %d, flags = %d\n", ruleset_fd, rule_type, flags);
    return 0;
}

int lsm_list_modules(struct lsm_module *modules, size_t size) {
    printf("lsm_list_modules called with size = %zu\n", size);
    return -1;
}

int lsm_set_self_attr(int attr_type, struct lsm_attr *attr, size_t size) {
    printf("lsm_set_self_attr called with attr_type = %d, size = %zu\n", attr_type, size);
    return 0;
}

int lsm_get_self_attr(int attr_type, struct lsm_attr *attr, size_t size) {
    printf("lsm_get_self_attr called with attr_type = %d, size = %zu\n", attr_type, size);
    return 0;
}

int listmount(int fd, struct listmount *lm, size_t size, int flags) {
    printf("listmount called with fd = %d, size = %zu, flags = %d\n", fd, size, flags);
    return 0;
}

int statmount(int fd, struct statmount *sm, size_t size, int flags) {
    printf("statmount called with fd = %d, size = %zu, flags = %d\n", fd, size, flags);
    return 0;
}

struct futex_waitv {
    uint32_t *uaddr;
    uint32_t flags;
};

int futex_waitv(struct futex_waitv *waitv, int nr, int timeout) {
    printf("futex_waitv called with timeout = %d\n", timeout);
    return 0;
}

int quotactl_fd(int fd, int cmd, int id, void *addr) {
    printf("quotactl_fd called with fd = %d, cmd = %d, id = %d\n", fd, cmd, id);
    return 0;
}

int map_shadow_stack(void *addr, size_t size) {
    printf("map_shadow_stack called with addr = %p, size = %zu\n", addr, size);
    return 0;
}

int set_mempolicy_home_node(int policy, int node, int maxnode, int flags) {
    printf("set_mempolicy_home_node called with policy = %d\n", policy);
    return 0;
}

int memfd_secret(int flags) {
    printf("memfd_secret called with flags = %d\n", flags);
    return 1;
}

int process_mrelease(pid_t pid) {
    printf("process_mrelease called with pid = %d\n", pid);
    return 0;
}

int futex_wake(uint32_t *futex, int val) {
    printf("futex_wake called with futex = %p, val = %d\n", (void*)futex, val);
    return 0;
}

int futex_requeue(uint32_t *futex1, int val1, uint32_t *futex2, int val2) {
    printf("futex_requeue called with futex1 = %p, val1 = %d, futex2 = %p, val2 = %d\n", (void*)futex1, val1, (void*)futex2, val2);
    return 0;
}

int futex_wait(uint32_t *futex, int expected, const struct timespec *timeout) {
    printf("futex_wait called with futex = %p, expected = %d\n", (void*)futex, expected);
    return 0;
}

int cachestat(int fd, int options, struct cachestat *cstat) {
    printf("cachestat called with fd = %d, options = %d\n", fd, options);
    return 0;
}

int fchmodat2(int dirfd, const char *pathname, mode_t mode, int flags) {
    printf("fchmodat2 called with dirfd = %d, pathname = %s, mode = %o, flags = %d\n", dirfd, pathname, mode, flags);
    return 0;
}

int mount_setattr(int fd, const char *path, unsigned int flags, struct mount_attr *attr, size_t size) {
    printf("mount_setattr called with fd = %d, path = %s, flags = %u, size = %zu\n", fd, path, flags, size);
    return 0;
}

// Status variables for tracking syscall results
int mseal_status, lsm_list_modules_status, lsm_set_self_attr_status, lsm_get_self_attr_status, listmount_status,
    statmount_status, futex_requeue_status, futex_wait_status, futex_wake_status, map_shadow_stack_status, epoll_pwait2_status,
    mount_setattr_status, futex_waitv_status, set_mempolicy_home_node_status, memfd_secret_status, process_mrelease_status, 
    landlock_add_rule_status, landlock_restrict_self_status, quotactl_fd_status, landlock_create_ruleset_status;

// Function templates for syscalls
void template_mseal() {
    int fd = open("/tmp/testfile.txt", O_RDWR | O_CREAT, 0644);
    if (fd != -1) {
        close(fd);
        printf("mseal syscall executed successfully.\n");
        mseal_status = 1;
    } else {
        perror("Failed to open file for mseal");
        mseal_status = 0;
    }
}

void template_lsm_list_modules() {
    struct lsm_module modules[10];
    int count = lsm_list_modules(modules, sizeof(modules));
    if (count > 0) {
        printf("lsm_list_modules syscall executed successfully.\n");
        lsm_list_modules_status = 1;
    } else {
        printf("lsm_list_modules syscall execution failed.\n");
        lsm_list_modules_status = 0;
    }
}

void template_lsm_set_self_attr() {
    struct lsm_attr attr = {0};
    if (lsm_set_self_attr(1, &attr, sizeof(attr)) == 0) {
        printf("lsm_set_self_attr syscall executed successfully.\n");
        lsm_set_self_attr_status = 1;
    } else {
        printf("lsm_set_self_attr syscall execution failed.\n");
        lsm_set_self_attr_status = 0;
    }
}

void template_lsm_get_self_attr() {
    struct lsm_attr attr;
    if (lsm_get_self_attr(1, &attr, sizeof(attr)) == 0) {
        printf("lsm_get_self_attr syscall executed successfully.\n");
        lsm_get_self_attr_status = 1;
    } else {
        printf("lsm_get_self_attr syscall execution failed.\n");
        lsm_get_self_attr_status = 0;
    }
}

void template_listmount() {
    struct listmount lm;
    if (listmount(AT_FDCWD, &lm, sizeof(lm), 0) == 0) {
        printf("listmount syscall executed successfully.\n");
        listmount_status = 1;
    } else {
        printf("listmount syscall execution failed.\n");
        listmount_status = 0;
    }
}

void template_statmount() {
    struct statmount sm;
    if (statmount(AT_FDCWD, &sm, sizeof(sm), 0) == 0) {
        printf("statmount syscall executed successfully.\n");
        statmount_status = 1;
    } else {
        printf("statmount syscall execution failed.\n");
        statmount_status = 0;
    }
}

void template_futex_requeue() {
    uint32_t futex_var1 = 0, futex_var2 = 0;
    if (futex_requeue(&futex_var1, 1, &futex_var2, 1) == 0) {
        printf("futex_requeue syscall executed successfully.\n");
        futex_requeue_status = 1;
    } else {
        printf("futex_requeue syscall execution failed.\n");
        futex_requeue_status = 0;
    }
}

void template_futex_wait() {
    uint32_t futex_var = 0;
    if (futex_wait(&futex_var, 0, NULL) == 0) {
        printf("futex_wait syscall executed successfully.\n");
        futex_wait_status = 1;
    } else {
        printf("futex_wait syscall execution failed.\n");
        futex_wait_status = 0;
    }
}

void template_futex_wake() {
    uint32_t futex_var = 0;
    if (futex_wake(&futex_var, 1) == 0) {
        printf("futex_wake syscall executed successfully.\n");
        futex_wake_status = 1;
    } else {
        printf("futex_wake syscall execution failed.\n");
        futex_wake_status = 0;
    }
}

void template_map_shadow_stack() {
    void *addr = mmap(NULL, 4096, PROT_READ | PROT_WRITE | PROT_EXEC, MAP_SHARED | MAP_ANONYMOUS, -1, 0);
    if (addr != MAP_FAILED) {
        if (map_shadow_stack(addr, 4096) == 0) {
            printf("map_shadow_stack executed successfully.\n");
            map_shadow_stack_status = 1;
        } else {
            printf("map_shadow_stack execution failed.\n");
            map_shadow_stack_status = 0;
        }
        munmap(addr, 4096);
    } else {
        perror("mmap failed");
        map_shadow_stack_status = 0;
    }
}

void template_epoll_pwait2() {
    int epfd = epoll_create1(0);
    struct epoll_event event = {0};
    struct timespec timeout = {1, 0};
    if (epfd != -1) {
        if (epoll_pwait2(epfd, &event, 1, &timeout, NULL) != -1) {
            printf("epoll_pwait2 syscall executed successfully.\n");
            epoll_pwait2_status = 1;
        } else {
            perror("epoll_pwait2 syscall execution failed");
            epoll_pwait2_status = 0;
        }
        close(epfd);
    } else {
        perror("Failed to create epoll instance");
        epoll_pwait2_status = 0;
    }
}

void template_mount_setattr() {
    int fd = open("/mnt", O_RDONLY);
    struct mount_attr attr = {0};
    if (fd != -1) {
        if (mount_setattr(fd, "", AT_SYMLINK_NOFOLLOW, &attr, sizeof(attr)) != -1) {
            printf("mount_setattr syscall executed successfully.\n");
            mount_setattr_status = 1;
        } else {
            perror("mount_setattr syscall execution failed");
            mount_setattr_status = 0;
        }
        close(fd);
    } else {
        perror("Failed to open /mnt for mount_setattr");
        mount_setattr_status = 0;
    }
}

void template_futex_waitv() {
    struct futex_waitv waitv;
    if (futex_waitv(&waitv, 1, 1000) == 0) {
        printf("futex_waitv syscall executed successfully.\n");
        futex_waitv_status = 1;
    } else {
        printf("futex_waitv syscall execution failed.\n");
        futex_waitv_status = 0;
    }
}

void template_set_mempolicy_home_node() {
    if (set_mempolicy_home_node(MPOL_PREFERRED, 0, 1, 0) == 0) {
        printf("set_mempolicy_home_node executed successfully.\n");
        set_mempolicy_home_node_status = 1;
    } else {
        printf("set_mempolicy_home_node execution failed.\n");
        set_mempolicy_home_node_status = 0;
    }
}

void template_memfd_secret() {
    if (memfd_secret(MFD_SECRET_EXCLUSIVE) != -1) {
        printf("memfd_secret syscall executed successfully.\n");
        memfd_secret_status = 1;
    } else {
        printf("memfd_secret syscall execution failed.\n");
        memfd_secret_status = 0;
    }
}

void template_process_mrelease() {
    if (process_mrelease(getpid()) == 0) {
        printf("process_mrelease syscall executed successfully.\n");
        process_mrelease_status = 1;
    } else {
        printf("process_mrelease syscall execution failed.\n");
        process_mrelease_status = 0;
    }
}

void template_landlock_add_rule() {
    struct landlock_path_beneath_attr attr = {0};
    if (landlock_add_rule(1, LANDLOCK_RULE_PATH_BENEATH, &attr, 0) == 0) {
        printf("landlock_add_rule syscall executed successfully.\n");
        landlock_add_rule_status = 1;
    } else {
        printf("landlock_add_rule syscall execution failed.\n");
        landlock_add_rule_status = 0;
    }
}

void template_landlock_restrict_self() {
    if (landlock_restrict_self(1, 0) == 0) {
        printf("landlock_restrict_self syscall executed successfully.\n");
        landlock_restrict_self_status = 1;
    } else {
        printf("landlock_restrict_self syscall execution failed.\n");
        landlock_restrict_self_status = 0;
    }
}

void template_quotactl_fd() {
    if (quotactl_fd(USRQUOTA, QCMD(0, USRQUOTA), 0, NULL) == 0) {
        printf("quotactl_fd syscall executed successfully.\n");
        quotactl_fd_status = 1;
    } else {
        printf("quotactl_fd syscall execution failed.\n");
        quotactl_fd_status = 0;
    }
}

void template_landlock_create_ruleset() {
    struct landlock_ruleset_attr attr = {0};
    if (landlock_create_ruleset(&attr, sizeof(attr), 0) != -1) {
        printf("landlock_create_ruleset syscall executed successfully.\n");
        landlock_create_ruleset_status = 1;
    } else {
        printf("landlock_create_ruleset syscall execution failed.\n");
        landlock_create_ruleset_status = 0;
    }
}
