



///===================================done till here =====================================




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



// Sync file range
#ifndef SYNC_FILE_RANGE_WRITE
#define SYNC_FILE_RANGE_WRITE 1
#endif
void template_sync_file_range() {
    int fd = open("/tmp/testfile.txt", O_RDWR);
    if (fd != -1) {
        // Using syscall for sync_file_range
        syscall(SYS_sync_file_range, fd, 0, 4096, SYNC_FILE_RANGE_WRITE);
        close(fd);
    }
}

// vmsplice
#ifndef SPLICE_F_GIFT
#define SPLICE_F_GIFT 0x10
#endif
void template_vmsplice() {
    int pipes[2];
    pipe(pipes);
    struct iovec iov = { "Hello, world!\n", 14 };
    // Using syscall for vmsplice
    syscall(SYS_vmsplice, pipes[1], &iov, 1, SPLICE_F_GIFT);
    close(pipes[0]);
    close(pipes[1]);
}

// move_pages
void template_move_pages() {
    void *pages[1] = {malloc(4096)};
    int nodes[1] = {0};
    // Using syscall for move_pages
    syscall(SYS_move_pages, 0, 1, pages, nodes, NULL, 0);
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

// Accept4
void template_accept4() {
    int sockfd = socket(AF_INET, SOCK_STREAM, 0);
    if (sockfd != -1) {
        struct sockaddr_in addr = {0};
        bind(sockfd, (struct sockaddr *)&addr, sizeof(addr));
        listen(sockfd, 10);
        accept4(sockfd, NULL, NULL, SOCK_NONBLOCK);  // The error is here
        close(sockfd);
    }
}


// Epoll_create1
void template_epoll_create1() {
    int epfd = epoll_create1(0);
    if (epfd != -1) {
        close(epfd);
    }
}

// Dup3
void template_dup3() {
    int fd = open("/tmp/testfile.txt", O_RDONLY);
    if (fd != -1) {
        int newfd = dup3(fd, fd + 1, O_CLOEXEC);  // This is also flagged with errors
        close(fd);
        close(newfd);
    }
}

// Pipe2
void template_pipe2() {
    int pipes[2];
    pipe2(pipes, O_NONBLOCK);  // Another missing function
    close(pipes[0]);
    close(pipes[1]);
}

// Inotify_init1
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







