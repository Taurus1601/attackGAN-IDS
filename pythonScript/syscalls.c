
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/mman.h>
#include <sys/uio.h>
#include <sys/socket.h>
#include <sys/epoll.h>
#include <sys/ioctl.h>
#include <sys/poll.h>
#include <sys/sendfile.h>
#include <sys/time.h>
#include <sys/times.h>
#include <sys/wait.h>
#include <sys/resource.h>
#include <sys/utsname.h>
#include <sys/sysinfo.h>
#include <sys/user.h>
#include <sys/ptrace.h>
#include <sys/reboot.h>
#include <sys/personality.h>
#include <sys/dir.h>
#include <sys/quota.h>
#include <sys/file.h>
#include <sys/eventfd.h>
#include <sys/signalfd.h>
#include <sys/timerfd.h>
#include <sys/fsuid.h>
#include <sys/xattr.h>
#include <linux/futex.h>
#include <linux/landlock.h>
#include <linux/bpf.h>
#include <linux/unistd.h>
#include <linux/keyctl.h>
#include <linux/mempolicy.h>
#include <linux/module.h>
#include <linux/netlink.h>
#include <linux/perf_event.h>
#include <linux/sched.h>
#include <linux/signal.h>
#include <linux/aio_abi.h>
#include <linux/rseq.h>
#include <linux/limits.h>
#include <linux/io_uring.h>
#include <linux/stat.h>
#include <linux/fanotify.h>
#include <fcntl.h>
#include <unistd.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <signal.h>
#include <sched.h>
#include <time.h>
#include <errno.h>
#include <pthread.h>
#include <poll.h>
#include <dirent.h>
#include <syscall.h>
#include <sys/inotify.h>
#include <sys/msg.h>
#include <sys/sem.h>
#include <sys/shm.h>
#include <sys/kexec.h>
#include <aio.h>
#include <linux/mount.h>
#include <stdint.h>
#include <arpa/inet.h>
#include <sys/select.h>
#include <sys/prctl.h>
#include <linux/fs.h>
#include <sys/io.h>
#include <sys/param.h>
#include <syslog.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <sys/statfs.h>
#include <sys/sysmacros.h>
#include <linux/capability.h>
#include <linux/quota.h>
#include <linux/utsname.h>
#include <sys/sched.h>
#include <sys/param.h>
#include <stdio.h>
#include <stdlib.h>
#include "syscalls.h"




void template_getrlimit() {
    struct rlimit rl;
    getrlimit(RLIMIT_NOFILE, &rl);
}

// getrusage
void template_getrusage() {
    struct rusage usage;
    getrusage(RUSAGE_SELF, &usage);
}

// sysinfo
void template_sysinfo() {
    struct sysinfo info;
    sysinfo(&info);
}

// times
void template_times() {
    struct tms buf;
    times(&buf);
}

// ptrace
void template_ptrace() {
    // PTRACE_TRACEME allows the process to be traced by its parent
    ptrace(PTRACE_TRACEME, 0, NULL, NULL);
}

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

// getppid
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

// capget
void template_capget() {
    struct __user_cap_header_struct hdr;
    struct __user_cap_data_struct data;
    hdr.version = _LINUX_CAPABILITY_VERSION_3;
    hdr.pid = 0;
    capget(&hdr, &data);
}

// capset
void template_capset() {
    struct __user_cap_header_struct hdr;
    struct __user_cap_data_struct data;
    hdr.version = _LINUX_CAPABILITY_VERSION_3;
    hdr.pid = 0;
    data.effective = 0;
    data.permitted = 0;
    data.inheritable = 0;
    capset(&hdr, &data);
}

// rt_sigpending
void template_rt_sigpending() {
    sigset_t set;
    sigemptyset(&set);
    rt_sigpending(&set, sizeof(set));
}

// rt_sigtimedwait
void template_rt_sigtimedwait() {
    sigset_t set;
    struct timespec timeout = {5, 0};
    siginfo_t info;
    sigemptyset(&set);
    sigaddset(&set, SIGINT);
    rt_sigtimedwait(&set, &info, &timeout, sizeof(set));
}

// rt_sigqueueinfo
void template_rt_sigqueueinfo() {
    pid_t pid = getpid();
    siginfo_t info;
    rt_sigqueueinfo(pid, SIGUSR1, &info);
}

// rt_sigsuspend
void template_rt_sigsuspend() {
    sigset_t mask;
    sigemptyset(&mask);
    rt_sigsuspend(&mask, sizeof(mask));
}

// getsockname
void template_getsockname() {
    int sockfd = socket(AF_INET, SOCK_STREAM, 0);
    struct sockaddr_in addr;
    socklen_t addrlen = sizeof(addr);
    if (sockfd != -1) {
        getsockname(sockfd, (struct sockaddr *)&addr, &addrlen);
        close(sockfd);
    }
}

// getpeername
void template_getpeername() {
    int sockfd = socket(AF_INET, SOCK_STREAM, 0);
    struct sockaddr_in addr;
    socklen_t addrlen = sizeof(addr);
    if (sockfd != -1) {
        // Connect to a server to make getpeername meaningful
        connect(sockfd, (struct sockaddr *)&addr, addrlen);
        getpeername(sockfd, (struct sockaddr *)&addr, &addrlen);
        close(sockfd);
    }
}

// socketpair
void template_socketpair() {
    int sv[2];
    socketpair(AF_UNIX, SOCK_STREAM, 0, sv);
    close(sv[0]);
    close(sv[1]);
}

// setsockopt
void template_setsockopt() {
    int sockfd = socket(AF_INET, SOCK_STREAM, 0);
    int optval = 1;
    setsockopt(sockfd, SOL_SOCKET, SO_REUSEADDR, &optval, sizeof(optval));
    close(sockfd);
}

// getsockopt
void template_getsockopt() {
    int sockfd = socket(AF_INET, SOCK_STREAM, 0);
    int optval;
    socklen_t optlen = sizeof(optval);
    getsockopt(sockfd, SOL_SOCKET, SO_REUSEADDR, &optval, &optlen);
    close(sockfd);
}

// clone
void template_clone() {
    // clone() requires specific flags and a stack, so it’s usually complex.
    // A simple placeholder to indicate where clone could be used.
}

// fork
void template_fork() {
    pid_t pid = fork();
    if (pid == 0) {
        // Child process
        exit(0);
    }
}

// vfork
void template_vfork() {
    pid_t pid = vfork();
    if (pid == 0) {
        // Child process
        _exit(0); // vfork requires _exit instead of exit
    }
}

// execve
void template_execve() {
    char *args[] = {"/bin/ls", NULL};
    execve(args[0], args, NULL);
}

// exit
void template_exit() {
    exit(0);
}

// wait4
void template_wait4() {
    pid_t pid = fork();
    if (pid == 0) {
        _exit(0);
    } else {
        int status;
        wait4(pid, &status, 0, NULL);
    }
}

// kill
void template_kill() {
    kill(getpid(), SIGTERM);
}

// newuname
void template_newuname() {
    struct utsname buffer;
    uname(&buffer);
}

// semget
void template_semget() {
    int semid = semget(IPC_PRIVATE, 1, IPC_CREAT | 0666);
    if (semid != -1) semctl(semid, 0, IPC_RMID);
}

// semop
void template_semop() {
    int semid = semget(IPC_PRIVATE, 1, IPC_CREAT | 0666);
    struct sembuf sop = {0, -1, 0};
    if (semid != -1) {
        semop(semid, &sop, 1);
        semctl(semid, 0, IPC_RMID);
    }
}

// semctl
void template_semctl() {
    int semid = semget(IPC_PRIVATE, 1, IPC_CREAT | 0666);
    if (semid != -1) {
        semctl(semid, 0, IPC_RMID);
    }
}

// shmdt
void template_shmdt() {
    int shmid = shmget(IPC_PRIVATE, 4096, IPC_CREAT | 0666);
    void *shmaddr = shmat(shmid, NULL, 0);
    shmdt(shmaddr);
    shmctl(shmid, IPC_RMID, NULL);
}

// msgget
void template_msgget() {
    int msgid = msgget(IPC_PRIVATE, IPC_CREAT | 0666);
    if (msgid != -1) msgctl(msgid, IPC_RMID, NULL);
}

// msgsnd
void template_msgsnd() {
    int msgid = msgget(IPC_PRIVATE, IPC_CREAT | 0666);
    struct { long mtype; char mtext[100]; } msg = {1, "Hello"};
    if (msgid != -1) {
        msgsnd(msgid, &msg, sizeof(msg.mtext), 0);
        msgctl(msgid, IPC_RMID, NULL);
    }
}

// msgrcv
void template_msgrcv() {
    int msgid = msgget(IPC_PRIVATE, IPC_CREAT | 0666);
    struct { long mtype; char mtext[100]; } msg;
    if (msgid != -1) {
        msgrcv(msgid, &msg, sizeof(msg.mtext), 1, 0);
        msgctl(msgid, IPC_RMID, NULL);
    }
}

// msgctl
void template_msgctl() {
    int msgid = msgget(IPC_PRIVATE, IPC_CREAT | 0666);
    if (msgid != -1) msgctl(msgid, IPC_RMID, NULL);
}

// fcntl
void template_fcntl() {
    int fd = open("/tmp/testfile.txt", O_RDWR | O_CREAT, 0644);
    if (fd != -1) {
        fcntl(fd, F_SETFL, O_NONBLOCK);
        close(fd);
    }
}

// flock
void template_flock() {
    int fd = open("/tmp/testfile.txt", O_RDWR | O_CREAT, 0644);
    if (fd != -1) {
        flock(fd, LOCK_EX);
        flock(fd, LOCK_UN);
        close(fd);
    }
}

// fsync
void template_fsync() {
    int fd = open("/tmp/testfile.txt", O_RDWR | O_CREAT, 0644);
    if (fd != -1) {
        fsync(fd);
        close(fd);
    }
}

// fdatasync
void template_fdatasync() {
    int fd = open("/tmp/testfile.txt", O_RDWR | O_CREAT, 0644);
    if (fd != -1) {
        fdatasync(fd);
        close(fd);
    }
}

// truncate
void template_truncate() {
    truncate("/tmp/testfile.txt", 100);
}

// ftruncate
void template_ftruncate() {
    int fd = open("/tmp/testfile.txt", O_RDWR | O_CREAT, 0644);
    if (fd != -1) {
        ftruncate(fd, 100);
        close(fd);
    }
}

// getdents
void template_getdents() {
    int fd = open("/tmp", O_RDONLY | O_DIRECTORY);
    char buf[1024];
    getdents(fd, (struct dirent *)buf, sizeof(buf));
    close(fd);
}

// getcwd
void template_getcwd() {
    char cwd[1024];
    getcwd(cwd, sizeof(cwd));
}

// chdir
void template_chdir() {
    chdir("/tmp");
}

// fchdir
void template_fchdir() {
    int fd = open("/tmp", O_RDONLY | O_DIRECTORY);
    if (fd != -1) {
        fchdir(fd);
        close(fd);
    }
}

// rename
void template_rename() {
    rename("/tmp/oldname.txt", "/tmp/newname.txt");
}

// mkdir
void template_mkdir() {
    mkdir("/tmp/testdir", 0755);
}

// rmdir
void template_rmdir() {
    rmdir("/tmp/testdir");
}

// creat
void template_creat() {
    int fd = creat("/tmp/testfile.txt", 0644);
    if (fd != -1) close(fd);
}

// link
void template_link() {
    link("/tmp/testfile.txt", "/tmp/testfile_link.txt");
}

// unlink
void template_unlink() {
    unlink("/tmp/testfile.txt");
}

// symlink
void template_symlink() {
    symlink("/tmp/testfile.txt", "/tmp/testfile_symlink.txt");
}

// readlink
void template_readlink() {
    char buf[1024];
    readlink("/tmp/testfile_symlink.txt", buf, sizeof(buf));
}

// chmod
void template_chmod() {
    chmod("/tmp/testfile.txt", 0644);
}

// fchmod
void template_fchmod() {
    int fd = open("/tmp/testfile.txt", O_RDWR);
    if (fd != -1) {
        fchmod(fd, 0644);
        close(fd);
    }
}

// chown
void template_chown() {
    chown("/tmp/testfile.txt", 1000, 1000); // Set to some user/group
}

// fchown
void template_fchown() {
    int fd = open("/tmp/testfile.txt", O_RDWR);
    if (fd != -1) {
        fchown(fd, 1000, 1000);
        close(fd);
    }
}

// lchown
void template_lchown() {
    lchown("/tmp/testfile_symlink.txt", 1000, 1000);
}

// umask
void template_umask() {
    umask(022);
}

// gettimeofday
void template_gettimeofday() {
    struct timeval tv;
    gettimeofday(&tv, NULL);
}

//

// access
void template_access() {
    int result = access("/tmp/testfile.txt", F_OK);
    if (result == 0) {
        printf("File exists\n");
    } else {
        printf("File does not exist\n");
    }
}

// pipe
void template_pipe() {
    int pipefd[2];
    if (pipe(pipefd) == 0) {
        write(pipefd[1], "Hello", 5);
        close(pipefd[0]);
        close(pipefd[1]);
    }
}

// select
void template_select() {
    fd_set readfds;
    struct timeval timeout;
    FD_ZERO(&readfds);
    FD_SET(0, &readfds); // stdin
    timeout.tv_sec = 5;
    timeout.tv_usec = 0;
    select(1, &readfds, NULL, NULL, &timeout);
}

// sched_yield
void template_sched_yield() {
    sched_yield();
}

// mremap
void template_mremap() {
    void *ptr = mmap(NULL, 4096, PROT_READ | PROT_WRITE, MAP_ANONYMOUS | MAP_PRIVATE, -1, 0);
    if (ptr != MAP_FAILED) {
        mremap(ptr, 4096, 8192, MREMAP_MAYMOVE);
        munmap(ptr, 8192);
    }
}

// msync
void template_msync() {
    int fd = open("/tmp/testfile.txt", O_RDWR);
    if (fd != -1) {
        void *map = mmap(NULL, 4096, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
        if (map != MAP_FAILED) {
            msync(map, 4096, MS_SYNC);
            munmap(map, 4096);
        }
        close(fd);
    }
}

// mincore
void template_mincore() {
    int fd = open("/tmp/testfile.txt", O_RDWR);
    if (fd != -1) {
        void *map = mmap(NULL, 4096, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
        if (map != MAP_FAILED) {
            unsigned char vec[1];
            mincore(map, 4096, vec);
            munmap(map, 4096);
        }
        close(fd);
    }
}

// madvise
void template_madvise() {
    int fd = open("/tmp/testfile.txt", O_RDWR);
    if (fd != -1) {
        void *map = mmap(NULL, 4096, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
        if (map != MAP_FAILED) {
            madvise(map, 4096, MADV_SEQUENTIAL);
            munmap(map, 4096);
        }
        close(fd);
    }
}

// shmget
void template_shmget() {
    int shmid = shmget(IPC_PRIVATE, 4096, IPC_CREAT | 0666);
    if (shmid != -1) {
        shmctl(shmid, IPC_RMID, NULL);
    }
}

// shmat
void template_shmat() {
    int shmid = shmget(IPC_PRIVATE, 4096, IPC_CREAT | 0666);
    if (shmid != -1) {
        void *shmaddr = shmat(shmid, NULL, 0);
        shmdt(shmaddr);
        shmctl(shmid, IPC_RMID, NULL);
    }
}

// shmctl
void template_shmctl() {
    int shmid = shmget(IPC_PRIVATE, 4096, IPC_CREAT | 0666);
    if (shmid != -1) {
        shmctl(shmid, IPC_RMID, NULL);
    }
}

// dup
void template_dup() {
    int fd = open("/tmp/testfile.txt", O_RDONLY);
    if (fd != -1) {
        int new_fd = dup(fd);
        close(fd);
        close(new_fd);
    }
}

// dup2
void template_dup2() {
    int fd = open("/tmp/testfile.txt", O_RDONLY);
    if (fd != -1) {
        dup2(fd, 1); // Duplicate to stdout
        close(fd);
    }
}

// pause
void template_pause() {
    pause(); // Wait for a signal to resume
}

// nanosleep
void template_nanosleep() {
    struct timespec ts;
    ts.tv_sec = 1;
    ts.tv_nsec = 0;
    nanosleep(&ts, NULL);
}

// getitimer
void template_getitimer() {
    struct itimerval timer;
    getitimer(ITIMER_REAL, &timer);
}

// alarm
void template_alarm() {
    alarm(5); // Set an alarm to go off in 5 seconds
}

// setitimer
void template_setitimer() {
    struct itimerval timer;
    timer.it_value.tv_sec = 1;
    timer.it_value.tv_usec = 0;
    timer.it_interval.tv_sec = 0;
    timer.it_interval.tv_usec = 0;
    setitimer(ITIMER_REAL, &timer, NULL);
}

// sendfile64
void template_sendfile64() {
    int source_fd = open("/tmp/source.txt", O_RDONLY);
    int dest_fd = open("/tmp/dest.txt", O_WRONLY | O_CREAT, 0644);
    off_t offset = 0;
    if (source_fd != -1 && dest_fd != -1) {
        sendfile(dest_fd, source_fd, &offset, 4096);
        close(source_fd);
        close(dest_fd);
    }
}

// accept
void template_accept() {
    int sockfd = socket(AF_INET, SOCK_STREAM, 0);
    struct sockaddr_in addr;
    addr.sin_family = AF_INET;
    addr.sin_port = htons(8080);
    addr.sin_addr.s_addr = INADDR_ANY;
    bind(sockfd, (struct sockaddr *)&addr, sizeof(addr));
    listen(sockfd, 1);
    accept(sockfd, NULL, NULL);
    close(sockfd);
}

// sendto
void template_sendto() {
    int sockfd = socket(AF_INET, SOCK_DGRAM, 0);
    struct sockaddr_in addr;
    addr.sin_family = AF_INET;
    addr.sin_port = htons(8080);
    inet_pton(AF_INET, "127.0.0.1", &addr.sin_addr);
    sendto(sockfd, "Hello", 5, 0, (struct sockaddr *)&addr, sizeof(addr));
    close(sockfd);
}

// recvfrom
void template_recvfrom() {
    int sockfd = socket(AF_INET, SOCK_DGRAM, 0);
    struct sockaddr_in addr;
    addr.sin_family = AF_INET;
    addr.sin_port = htons(8080);
    addr.sin_addr.s_addr = INADDR_ANY;
    bind(sockfd, (struct sockaddr *)&addr, sizeof(addr));
    char buffer[100];
    recvfrom(sockfd, buffer, 100, 0, NULL, NULL);
    close(sockfd);
}

// sendmsg
void template_sendmsg() {
    int sockfd = socket(AF_INET, SOCK_DGRAM, 0);
    struct sockaddr_in addr;
    struct msghdr msg;
    struct iovec iov;
    char message[] = "Hello";
    iov.iov_base = message;
    iov.iov_len = sizeof(message);
    msg.msg_name = &addr;
    msg.msg_namelen = sizeof(addr);
    msg.msg_iov = &iov;
    msg.msg_iovlen = 1;
    sendmsg(sockfd, &msg, 0);
    close(sockfd);
}

// recvmsg
void template_recvmsg() {
    int sockfd = socket(AF_INET, SOCK_DGRAM, 0);
    struct sockaddr_in addr;
    struct msghdr msg;
    struct iovec iov;
    char buffer[100];
    iov.iov_base = buffer;
    iov.iov_len = sizeof(buffer);
    msg.msg_name = &addr;
    msg.msg_namelen = sizeof(addr);
    msg.msg_iov = &iov;
    msg.msg_iovlen = 1;
    recvmsg(sockfd, &msg, 0);
    close(sockfd);
}

// shutdown
void template_shutdown() {
    int sockfd = socket(AF_INET, SOCK_STREAM, 0);
    if (sockfd != -1) {
        shutdown(sockfd, SHUT_RDWR);
        close(sockfd);
    }
}

// bind
void template_bind() {
    int sockfd = socket(AF_INET, SOCK_STREAM, 0);
    struct sockaddr_in addr;
    addr.sin_family = AF_INET;
    addr.sin_port = htons(8080);
    addr.sin_addr.s_addr = INADDR_ANY;
    bind(sockfd, (struct sockaddr *)&addr, sizeof(addr));
    close(sockfd);
}

// listen
void template_listen() {
    int sockfd = socket(AF_INET, SOCK_STREAM, 0);
    struct sockaddr_in addr;
    addr.sin_family = AF_INET;
    addr.sin_port = htons(8080);
    addr.sin_addr.s_addr = INADDR_ANY;
    bind(sockfd, (struct sockaddr *)&addr, sizeof(addr));
    listen(sockfd, 5);
    close(sockfd);
}

// newstat
void template_newstat() {
    struct stat sb;
    stat("/tmp/testfile.txt", &sb);
}

// newfstat
void template_newfstat() {
    int fd = open("/tmp/testfile.txt", O_RDONLY);
    struct stat sb;
    if (fd != -1) {
        fstat(fd, &sb);
        close(fd);
    }
}

// newlstat
void template_newlstat() {
    struct stat sb;
    lstat("/tmp/testfile.txt", &sb);
}

// poll
void template_poll() {
    struct pollfd fds[1];
    fds[0].fd = 0; // stdin
    fds[0].events = POLLIN;
    poll(fds, 1, 1000);
}

// lseek
void template_lseek() {
    int fd = open("/tmp/testfile.txt", O_RDONLY);
    if (fd != -1) {
        lseek(fd, 0, SEEK_END);
        close(fd);
    }
}

// mprotect
void template_mprotect() {
    int fd = open("/tmp/testfile.txt", O_RDWR);
    if (fd != -1) {
        void *map = mmap(NULL, 4096, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
        if (map != MAP_FAILED) {
            mprotect(map, 4096, PROT_READ);
            munmap(map, 4096);
        }
        close(fd);
    }
}

// brk
void template_brk() {
    void *current_brk = sbrk(0);
    brk(current_brk + 4096); // Increase brk by 4096 bytes
}

// rt_sigaction
void template_rt_sigaction() {
    struct sigaction sa;
    sa.sa_handler = SIG_IGN;
    sigaction(SIGINT, &sa, NULL);
}

// rt_sigprocmask
void template_rt_sigprocmask() {
    sigset_t set;
    sigemptyset(&set);
    sigaddset(&set, SIGINT);
    sigprocmask(SIG_BLOCK, &set, NULL);
}

// rt_sigreturn
void template_rt_sigreturn() {
    // This is a placeholder. rt_sigreturn is used by the kernel to return from a signal handler.
    // It is generally not called directly by user-space programs.
}

// pread64
void template_pread64() {
    int fd = open("/tmp/testfile.txt", O_RDONLY);
    char buffer[100];
    if (fd != -1) {
        pread64(fd, buffer, 100, 0);
        close(fd);
    }
}

// pwrite64
void template_pwrite64() {
    int fd = open("/tmp/testfile.txt", O_WRONLY | O_CREAT, 0644);
    if (fd != -1) {
        pwrite64(fd, "Hello, world!\n", 14, 0);
        close(fd);
    }
}

// readv
void template_readv() {
    int fd = open("/tmp/testfile.txt", O_RDONLY);
    char buffer1[50], buffer2[50];
    struct iovec iov[2];
    iov[0].iov_base = buffer1;
    iov[0].iov_len = sizeof(buffer1);
    iov[1].iov_base = buffer2;
    iov[1].iov_len = sizeof(buffer2);
    if (fd != -1) {
        readv(fd, iov, 2);
        close(fd);
    }
}

// writev
void template_writev() {
    int fd = open("/tmp/testfile.txt", O_WRONLY | O_CREAT, 0644);
    if (fd != -1) {
        struct iovec iov[2];
        iov[0].iov_base = "Hello, ";
        iov[0].iov_len = 7;
        iov[1].iov_base = "world!\n";
        iov[1].iov_len = 7;
        writev(fd, iov, 2);
        close(fd);
    }
}

// read
void template_read() {
    int fd = open("/tmp/testfile.txt", O_RDONLY);
    char buffer[100];
    if (fd != -1) {
        read(fd, buffer, sizeof(buffer));
        close(fd);
    }
}

// write
void template_write() {
    int fd = open("/tmp/testfile.txt", O_WRONLY | O_CREAT, 0644);
    if (fd != -1) {
        write(fd, "Hello, world!\n", 14);
        close(fd);
    }
}

// open
void template_open() {
    int fd = open("/tmp/testfile.txt", O_RDONLY);
    if (fd != -1) close(fd);
}

// close
void template_close() {
    int fd = open("/tmp/testfile.txt", O_RDONLY);
    if (fd != -1) close(fd);
}

// newstat
void template_newstat() {
    struct stat sb;
    stat("/tmp/testfile.txt", &sb);
}

// newfstat
void template_newfstat() {
    int fd = open("/tmp/testfile.txt", O_RDONLY);
    struct stat sb;
    if (fd != -1) {
        fstat(fd, &sb);
        close(fd);
    }
}

// newlstat
void template_newlstat() {
    struct stat sb;
    lstat("/tmp/testfile.txt", &sb);
}

// poll
void template_poll() {
    struct pollfd fds[1];
    fds[0].fd = 0; // stdin
    fds[0].events = POLLIN;
    poll(fds, 1, 1000);
}

// lseek
void template_lseek() {
    int fd = open("/tmp/testfile.txt", O_RDONLY);
    if (fd != -1) {
        lseek(fd, 0, SEEK_END);
        close(fd);
    }
}

// mmap
void template_mmap() {
    int fd = open("/tmp/testfile.txt", O_RDWR);
    if (fd != -1) {
        void *map = mmap(NULL, 4096, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
        if (map != MAP_FAILED) {
            munmap(map, 4096);
        }
        close(fd);
    }
}

// mprotect
void template_mprotect() {
    int fd = open("/tmp/testfile.txt", O_RDWR);
    if (fd != -1) {
        void *map = mmap(NULL, 4096, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
        if (map != MAP_FAILED) {
            mprotect(map, 4096, PROT_READ);
            munmap(map, 4096);
        }
        close(fd);
    }
}

// munmap
void template_munmap() {
    int fd = open("/tmp/testfile.txt", O_RDWR);
    void *map = mmap(NULL, 4096, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
    if (map != MAP_FAILED) {
        munmap(map, 4096);
    }
    close(fd);
}

// brk
void template_brk() {
    void *current_brk = sbrk(0);
    brk(current_brk + 4096); // Increase brk by 4096 bytes
}

// rt_sigaction
void template_rt_sigaction() {
    struct sigaction sa;
    sa.sa_handler = SIG_IGN;
    sigaction(SIGINT, &sa, NULL);
}

// rt_sigprocmask
void template_rt_sigprocmask() {
    sigset_t set;
    sigemptyset(&set);
    sigaddset(&set, SIGINT);
    sigprocmask(SIG_BLOCK, &set, NULL);
}

// ioctl
void template_ioctl() {
    int fd = open("/dev/null", O_RDWR);
    if (fd != -1) {
        ioctl(fd, 0); // Placeholder argument
        close(fd);
    }
}

// pread64
void template_pread64() {
    int fd = open("/tmp/testfile.txt", O_RDONLY);
    char buffer[100];
    if (fd != -1) {
        pread64(fd, buffer, 100, 0);
        close(fd);
    }
}

// pwrite64
void template_pwrite64() {
    int fd = open("/tmp/testfile.txt", O_WRONLY | O_CREAT, 0644);
    if (fd != -1) {
        pwrite64(fd, "Hello, world!\n", 14, 0);
        close(fd);
    }
}

// socket
void template_socket() {
    int sockfd = socket(AF_INET, SOCK_STREAM, 0);
    if (sockfd != -1) close(sockfd);
}

// connect
void template_connect() {
    int sockfd = socket(AF_INET, SOCK_STREAM, 0);
    if (sockfd != -1) {
        struct sockaddr_in server;
        server.sin_family = AF_INET;
        server.sin_port = htons(80);
        inet_pton(AF_INET, "192.168.1.1", &server.sin_addr);
        connect(sockfd, (struct sockaddr *)&server, sizeof(server));
        close(sockfd);
    }
}

// execve
void template_execve() {
    char *args[] = {"/bin/ls", NULL};
    execve(args[0], args, NULL);
}

// fork
void template_fork() {
    pid_t pid = fork();
    if (pid == 0) {
        // Child process
        exit(0);
    }
}

// kill
void template_kill() {
    kill(getpid(), SIGTERM);  // Sends SIGTERM to self
}

// getpid
void template_getpid() {
    pid_t pid = getpid();
}


// setdomainname
void template_setdomainname() {
    setdomainname("example.com", 11); // Set domain name, requires root privileges
}

// iopl
void template_iopl() {
    iopl(3); // Set I/O privilege level, requires root privileges
}

// ioperm
void template_ioperm() {
    ioperm(0x378, 3, 1); // Grant I/O permissions for a range of ports, requires root privileges
}

// init_module
void template_init_module() {
    // Placeholder; usually requires a binary module image and root privileges
    init_module(NULL, 0, ""); 
}

// delete_module
void template_delete_module() {
    delete_module("module_name", O_NONBLOCK); // Unload a kernel module, requires root
}

// quotactl
void template_quotactl() {
    struct dqblk dq;
    quotactl(QCMD(Q_GETQUOTA, USRQUOTA), "/dev/sda1", 1000, (caddr_t)&dq); // Requires root privileges
}

// gettid
void template_gettid() {
    pid_t tid = gettid(); // Get the thread ID
}

// readahead
void template_readahead() {
    int fd = open("/tmp/testfile.txt", O_RDONLY);
    if (fd != -1) {
        readahead(fd, 0, 4096);
        close(fd);
    }
}

// setxattr
void template_setxattr() {
    setxattr("/tmp/testfile.txt", "user.attr", "value", 5, 0);
}

// lsetxattr
void template_lsetxattr() {
    lsetxattr("/tmp/testfile.txt", "user.attr", "value", 5, 0);
}

// fsetxattr
void template_fsetxattr() {
    int fd = open("/tmp/testfile.txt", O_WRONLY);
    if (fd != -1) {
        fsetxattr(fd, "user.attr", "value", 5, 0);
        close(fd);
    }
}

// getxattr
void template_getxattr() {
    char value[100];
    getxattr("/tmp/testfile.txt", "user.attr", value, sizeof(value));
}

// lgetxattr
void template_lgetxattr() {
    char value[100];
    lgetxattr("/tmp/testfile.txt", "user.attr", value, sizeof(value));
}

// fgetxattr
void template_fgetxattr() {
    int fd = open("/tmp/testfile.txt", O_RDONLY);
    if (fd != -1) {
        char value[100];
        fgetxattr(fd, "user.attr", value, sizeof(value));
        close(fd);
    }
}

// listxattr
void template_listxattr() {
    char list[100];
    listxattr("/tmp/testfile.txt", list, sizeof(list));
}

// llistxattr
void template_llistxattr() {
    char list[100];
    llistxattr("/tmp/testfile.txt", list, sizeof(list));
}

// flistxattr
void template_flistxattr() {
    int fd = open("/tmp/testfile.txt", O_RDONLY);
    if (fd != -1) {
        char list[100];
        flistxattr(fd, list, sizeof(list));
        close(fd);
    }
}

// removexattr
void template_removexattr() {
    removexattr("/tmp/testfile.txt", "user.attr");
}

// lremovexattr
void template_lremovexattr() {
    lremovexattr("/tmp/testfile.txt", "user.attr");
}

// fremovexattr
void template_fremovexattr() {
    int fd = open("/tmp/testfile.txt", O_WRONLY);
    if (fd != -1) {
        fremovexattr(fd, "user.attr");
        close(fd);
    }
}

// tkill
void template_tkill() {
    pid_t tid = gettid();
    tkill(tid, SIGTERM);
}

// time
void template_time() {
    time_t t = time(NULL);
}

// futex
void template_futex() {
    int futex_var = 0;
    futex(&futex_var, FUTEX_WAIT, 0, NULL, NULL, 0); // Placeholder
}

// sched_setaffinity
void template_sched_setaffinity() {
    cpu_set_t mask;
    CPU_ZERO(&mask);
    CPU_SET(0, &mask); // Assign process to CPU 0
    sched_setaffinity(0, sizeof(mask), &mask);
}

// sched_getaffinity
void template_sched_getaffinity() {
    cpu_set_t mask;
    CPU_ZERO(&mask);
    sched_getaffinity(0, sizeof(mask), &mask);
}

// io_setup
void template_io_setup() {
    aio_context_t ctx = 0;
    io_setup(1, &ctx); // Placeholder for I/O context
}

// io_destroy
void template_io_destroy() {
    aio_context_t ctx = 0;
    io_destroy(ctx);
}

// io_getevents
void template_io_getevents() {
    aio_context_t ctx = 0;
    struct io_event events[10];
    io_getevents(ctx, 1, 10, events, NULL);
}

// io_submit
void template_io_submit() {
    aio_context_t ctx = 0;
    struct iocb cb;
    struct iocb *cbs[1] = { &cb };
    io_submit(ctx, 1, cbs);
}

// io_cancel
void template_io_cancel() {
    aio_context_t ctx = 0;
    struct iocb cb;
    struct io_event event;
    io_cancel(ctx, &cb, &event);
}

// sigaltstack
void template_sigaltstack() {
    stack_t ss;
    ss.ss_sp = malloc(SIGSTKSZ);
    ss.ss_size = SIGSTKSZ;
    ss.ss_flags = 0;
    sigaltstack(&ss, NULL);
    free(ss.ss_sp);
}

// utime
void template_utime() {
    struct utimbuf times;
    times.actime = 1627849142; // Access time
    times.modtime = 1627849142; // Modification time
    utime("/tmp/testfile.txt", &times);
}

// mknod
void template_mknod() {
    mknod("/tmp/testnode", S_IFREG | 0644, 0);
}

// personality
void template_personality() {
    personality(0); // Reset to default personality
}

// ustat
void template_ustat() {
    struct ustat info;
    ustat(0, &info); // Check file system information (requires appropriate device)
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

// sysfs
void template_sysfs() {
    sysfs(1); // Retrieve file system type (usage varies)
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

// mlockall
void template_mlockall() {
    mlockall(MCL_CURRENT | MCL_FUTURE);
}

// munlockall
void template_munlockall() {
    munlockall();
}

// vhangup
void template_vhangup() {
    vhangup();
}

// modify_ldt
void template_modify_ldt() {
    modify_ldt(0, NULL, 0); // Placeholder; generally requires kernel module or privileges
}

// pivot_root
void template_pivot_root() {
    pivot_root("/new_root", "/old_root"); // Requires root privileges
}

// prctl
void template_prctl() {
    prctl(PR_SET_NAME, "new_name", 0, 0, 0);
}

// arch_prctl
void template_arch_prctl() {
    arch_prctl(ARCH_SET_FS, 0);
}

// adjtimex
void template_adjtimex() {
    struct timex t;
    adjtimex(&t);
}

// setrlimit
void template_setrlimit() {
    struct rlimit rl;
    rl.rlim_cur = 1024;
    rl.rlim_max = 2048;
    setrlimit(RLIMIT_NOFILE, &rl);
}

// chroot
void template_chroot() {
    chroot("/new_root"); // Requires root privileges
}

// sync
void template_sync() {
    sync();
}

// acct
void template_acct() {
    acct("/tmp/accounting_file"); // Enable process accounting (requires root)
}

// settimeofday
void template_settimeofday() {
    struct timeval tv;
    tv.tv_sec = 1627849142;
    tv.tv_usec = 0;
    settimeofday(&tv, NULL);
}

// mount
void template_mount() {
    mount("none", "/mnt", "tmpfs", 0, NULL); // Requires root privileges
}

// umount
void template_umount() {
    umount("/mnt"); // Requires root privileges
}

// swapon
void template_swapon() {
    swapon("/swapfile", 0); // Requires root privileges
}

// swapoff
void template_swapoff() {
    swapoff("/swapfile"); // Requires root privileges
}

// reboot
void template_reboot() {
    reboot(RB_AUTOBOOT); // Requires root privileges
}

// sethostname
void template_sethostname() {
    sethostname("new_hostname", 12);
}


// mbind
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
