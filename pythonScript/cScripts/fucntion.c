void template_read(void);
void template_write(void);
void template_open(void);
void template_close(void);
void template_stat(void);
void template_fstat(void);
void template_lstat(void);
void template_poll(void);
void template_lseek(void);
void template_mmap(void);
void template_mprotect(void);
void template_munmap(void);
void template_brk(void);
void template_rt_sigaction(void);
void template_rt_sigprocmask(void);
void template_rt_sigreturn(void);
void template_ioctl(void);
void template_pread64(void);
void template_pwrite64(void);
void template_readv(void);
void template_writev(void);
void template_getsockname(void);
void template_getpeername(void);
void template_socketpair(void);
void template_setsockopt(void);
void template_getsockopt(void);
void template_clone(void);
void template_vfork(void);
void template_execve(void);
void template_exit(void);
void template_wait4(void);
void template_kill(void);
void template_newuname(void);
void template_semget(void);
void template_semop(void);
void template_semctl(void);
void template_shmdt(void);
void template_msgget(void);
void template_msgsnd(void);
void template_msgrcv(void);
void template_msgctl(void);
void template_fcntl(void);
void template_flock(void);
void template_fsync(void);
void template_fdatasync(void);
void template_truncate(void);
void template_ftruncate(void);
void template_getdents(void);
void template_getcwd(void);
void template_chdir(void);
void template_fchdir(void);
void template_rename(void);
void template_mkdir(void);
void template_rmdir(void);
void template_creat(void);
void template_link(void);
void template_unlink(void);
void template_symlink(void);
void template_readlink(void);
void template_chmod(void);
void template_fchmod(void);
void template_chown(void);
void template_fchown(void);
void template_lchown(void);
void template_umask(void);
void template_gettimeofday(void);
void template_settimeofday(void);
void template_getitimer(void);
void template_setitimer(void);
void template_clock_gettime(void);
void template_clock_settime(void);
void template_clock_getres(void);
void template_clock_nanosleep(void);
void template_getpid(void);
void template_gettid(void);
void template_getuid(void);
void template_getgid(void);
void template_geteuid(void);
void template_getegid(void);
void template_setuid(void);
void template_setgid(void);
void template_setreuid(void);
void template_setregid(void);
void template_getgroups(void);
void template_setgroups(void);
void template_setresuid(void);
void template_getresuid(void);
void template_setresgid(void);
void template_getresgid(void);
void template_getpgid(void);
void template_setpgid(void);
void template_getppid(void);
void template_getpgrp(void);
void template_setsid(void);
void template_sysinfo(void);
void template_syslog(void);
void template_setrlimit(void);
void template_getrusage(void);
void template_prctl(void);
void template_arch_prctl(void);
void template_mount(void);
void template_umount(void);
void template_swapon(void);
void template_swapoff(void);
void template_reboot(void);
void template_sethostname(void);
void template_setdomainname(void);
void template_mlock(void);
void template_munlock(void);
void template_mlockall(void);
void template_munlockall(void);
void template_mincore(void);
void template_madvise(void);
void template_mremap(void);
void template_setxattr(void);
void template_lsetxattr(void);
void template_fsetxattr(void);
void template_getxattr(void);
void template_lgetxattr(void);
void template_fgetxattr(void);
void template_listxattr(void);
void template_llistxattr(void);
void template_flistxattr(void);
void template_removexattr(void);
void template_lremovexattr(void);
void template_fremovexattr(void);
void template_io_setup(void);
void template_io_destroy(void);
void template_io_submit(void);
void template_io_cancel(void);
void template_io_getevents(void);
void template_sched_yield(void);
void template_sched_setparam(void);
void template_sched_getparam(void);
void template_sched_setscheduler(void);
void template_sched_getscheduler(void);
void template_sched_get_priority_max(void);
void template_sched_get_priority_min(void);
void template_sched_rr_get_interval(void);
void template_sched_setaffinity(void);
void template_sched_getaffinity(void);
void template_capget(void);
void template_capset(void);
void template_quotactl(void);
void template_init_module(void);
void template_delete_module(void);
void template_sigaltstack(void);
void template_rt_sigpending(void);
void template_rt_sigtimedwait(void);
void template_rt_sigqueueinfo(void);
void template_rt_sigsuspend(void);
void template_sched_setattr(void);
void template_sched_getattr(void);
void template_renameat(void);
void template_renameat2(void);
void template_openat2(void);
void template_pidfd_send_signal(void);
void template_pidfd_open(void);
void template_clone3(void);
void template_close_range(void);
void template_faccessat(void);
void template_faccessat2(void);
void template_fchmodat(void);
void template_fchownat(void);
void template_fstatat(void);
void template_linkat(void);
void template_mkdirat(void);
void template_mknodat(void);
void template_newfstatat(void);
void template_readlinkat(void);
void template_symlinkat(void);
void template_unlinkat(void);
void template_move_pages(void);
void template_migrate_pages(void);
void template_mbind(void);
void template_get_mempolicy(void);
void template_set_mempolicy(void);
void template_userfaultfd(void);
void template_pkey_alloc(void);
void template_pkey_free(void);
void template_pkey_mprotect(void);
void template_name_to_handle_at(void);
void template_open_by_handle_at(void);
void template_sync_file_range(void);
void template_vmsplice(void);
void template_splice(void);
void template_tee(void);
void template_fallocate(void);
void template_readahead(void);
void template_syncfs(void);
void template_setns(void);
void template_recvmmsg(void);
void template_sendmmsg(void);
void template_socket_accept4(void);
void template_socket_bind(void);
void template_socket_connect(void);
void template_socket_listen(void);
void template_socket_shutdown(void);
void template_socket_getsockopt(void);
void template_socket_setsockopt(void);
void template_timerfd_create(void);
void template_timerfd_settime(void);
void template_timerfd_gettime(void);
void template_clock_adjtime(void);
void template_clock_getres(void);
void template_clock_nanosleep(void);
void template_seccomp(void);
void template_prctl_set_seccomp(void);
void template_landlock_create_ruleset(void);
void template_landlock_add_rule(void);
void template_landlock_restrict_self(void);
void template_epoll_create1(void);
void template_epoll_pwait(void);
void template_epoll_pwait2(void);
void template_eventfd(void);
void template_eventfd2(void);
void template_signalfd(void);
void template_signalfd4(void);
void template_timerfd_create(void);
void template_prlimit(void);
void template_getrlimit(void);
void template_utime(void);
void template_utimensat(void);
void template_futimesat(void);
void template_set_tid_address(void);
void template_set_robust_list(void);
void template_get_robust_list(void);
void template_futex(void);
void template_futex_waitv(void);
void template_remap_file_pages(void);
void template_memfd_create(void);
void template_membarrier(void);
void template_copy_file_range(void);
void template_getrandom(void);
void template_memfd_secret(void);
void template_process_madvise(void);
void template_process_mrelease(void);
void template_statx(void);
void template_lookup_dcookie(void);
void template_request_key(void);
void template_keyctl(void);
void template_ioprio_set(void);
void template_ioprio_get(void);
void template_add_key(void);
void template_inotify_init1(void);
void template_fanotify_init(void);
void template_fanotify_mark(void);
void template_fsconfig(void);
void template_fsopen(void);
void template_fsmount(void);
void template_fspick(void);
void template_mount_setattr(void);
void template_open_tree(void);
void template_move_mount(void);
void template_bpf(void);
void template_bpf_map_create(void);
void template_bpf_prog_load(void);
void template_io_pgetevents(void);
void template_rseq(void);
void template_pidfd_getfd(void);
void template_pidfd_setfd(void);
void template_pidfd_getinfo(void);
void template_pidfd_autopick(void);
void template_entry_rseq_syscall(void);
void template_mount_change_attr(void);
void template_mount_has_submounts(void);
void template_mount_is_mounted(void);
void template_mount_get_fstype(void);
void template_mount_iterate(void);
void template_mount_get_parent(void);
void template_mount_get_devname(void);
void template_mount_get_target(void);
void template_mount_get_source(void);
void template_mq_notify_2(void);
void template_mq_timedsend_time64(void);
void template_mq_timedreceive_time64(void);
void template_semtimedop_time64(void);
void template_semget_2(void);
void template_msgget_2(void);
void template_shmget_2(void);
void template_shm_open(void);
void template_shm_unlink(void);
void template_mq_open_2(void);
void template_statx_sync(void);
void template_copy_file_range_2(void);
void template_fs_freeze(void);
void template_fs_thaw(void);
void template_fs_get_stats(void);
void template_fs_set_stats(void);
void template_fs_query_stats(void);
void template_fs_get_info(void);
void template_fs_set_info(void);
void template_fs_query_info(void);
void template_process_vm_readv(void);
void template_process_vm_writev(void);
void template_get_mempolicy_2(void);
void template_set_mempolicy_2(void);
void template_mbind_2(void);
void template_migrate_pages_2(void);
void template_move_pages_2(void);
void template_accept4_2(void);
void template_recvmmsg_time64(void);
void template_sendmmsg_2(void);
void template_socket_get_local(void);
void template_socket_get_peer(void);
void template_socket_get_opt_2(void);
void template_socket_set_opt_2(void);
void template_socket_get_error(void);
void template_socket_get_type(void);
void template_execveat(void);
void template_execveat_2(void);
void template_clone_3(void);
void template_fork_2(void);
void template_vfork_2(void);
void template_wait4_2(void);
void template_waitid_2(void);
void template_landlock_add_rule_2(void);
void template_landlock_restrict_self_2(void);
void template_seccomp_2(void);
void template_seccomp_get_action(void);
void template_seccomp_get_filter(void);
void template_seccomp_get_notif(void);
void template_seccomp_get_stats(void);
void template_prlimit64_2(void);
void template_getrlimit64_2(void);
void template_setrlimit64_2(void);
void template_utime_2(void);
void template_utimensat_2(void);
void template_futimesat_2(void);
void template_bpf_map_update(void);
void template_bpf_map_lookup(void);
void template_bpf_map_delete(void);
void template_bpf_map_get_next_key(void);
void template_bpf_prog_test_run(void);
void template_bpf_prog_get_next_id(void);
void template_bpf_prog_get_fd_by_id(void);
void template_bpf_obj_get_info_by_fd(void);
void template_bpf_raw_tracepoint_open(void);
void template_bpf_task_fd_query(void);
void template_io_uring_setup(void);
void template_io_uring_enter(void);
void template_io_uring_register(void);
void template_io_uring_setup2(void);
void template_io_uring_enter2(void);
void template_io_uring_register2(void);
void template_clock_gettime64(void);
void template_clock_settime64(void);
void template_clock_getres_time64(void);
void template_clock_nanosleep_time64(void);
void template_timer_gettime64(void);
void template_timer_settime64(void);
void template_timerfd_gettime64(void);
void template_timerfd_settime64(void);
void template_membarrier_2(void);
void template_copy_file_range_3(void);
void template_getrandom_2(void);
void template_memfd_secret_2(void);
void template_process_madvise_2(void);
void template_statx_2(void);
void template_lookup_dcookie_2(void);
void template_request_key_2(void);
void template_keyctl_2(void);
void template_ioprio_get_2(void);
void template_process_vm_writev(void);
void template_process_vm_readv(void);
void template_kexec_file_load(void);
void template_perf_event_open(void);
void template_rseq_register(void);
void template_rseq_unregister(void);
void template_fsopen_2(void);
void template_fspick_2(void);
void template_fsconfig_2(void);
void template_fsmount_2(void);
void template_mount_setattr_2(void);
void template_landlock_restrict_self_3(void);
void template_process_mrelease_2(void);
void template_futex_wait(void);
void template_futex_wake(void);
void template_futex_requeue(void);
void template_futex_waitv_2(void);
void template_set_thread_area(void);
void template_get_thread_area(void);
void template_io_pgetevents_2(void);
void template_rseq_2(void);
void template_statmount(void);
void template_fstatmount(void);
void template_statmount_2(void);
void template_fstatmount_2(void);
void template_mount_fd(void);
void template_clone_pidfd(void);
void template_memfd_create_2(void);
void template_memfd_create_3(void);
void template_pidfd_wait(void);
void template_pidfd_recv(void);
void template_pidfd_close(void);
void template_pidfd_query(void);
void template_pidfd_create(void);
void template_pidfd_move(void);
void template_pidfd_copy(void);
void template_pidfd_send(void);
void template_pidfd_recv_msg(void);
void template_pidfd_send_msg(void);
void template_pidfd_get_pid(void);
void template_pidfd_get_tid(void);
void template_pidfd_get_tgid(void);
void template_pidfd_get_pgid(void);
void template_pidfd_get_sid(void);
void template_pidfd_get_uid(void);
void template_pidfd_get_gid(void);
void template_pidfd_get_groups(void);
void template_pidfd_get_comm(void);
void template_pidfd_get_exe(void);
void template_pidfd_get_cwd(void);
void template_pidfd_get_root(void);
void template_pidfd_get_ns(void);
void template_pidfd_get_fd(void);
void template_pidfd_get_fdinfo(void);
void template_pidfd_get_maps(void);
void template_pidfd_get_auxv(void);
void template_pidfd_get_environ(void);
void template_pidfd_get_limits(void);
void template_pidfd_get_status(void);
void template_pidfd_get_stat(void);
void template_pidfd_get_statm(void);
void template_pidfd_get_wchan(void);
void template_pidfd_get_syscall(void);
void template_pidfd_get_stack(void);
void template_pidfd_get_children(void);
void template_pidfd_get_threads(void);
void template_pidfd_get_task(void);
void template_openat2_2(void);
void template_pidfd_setns(void);
void template_pidfd_mount(void);
void template_pidfd_umount(void);
void template_pidfd_pivot_root(void);
void template_pidfd_chroot(void);
void template_pidfd_chdir(void);
void template_pidfd_fchdir(void);
void template_pidfd_getcwd(void);
void template_pidfd_open_tree(void);
void template_pidfd_move_mount(void);
void template_pidfd_open_2(void);
void template_pidfd_send_signal_2(void);
void template_clone_into_pid(void);
void template_mount_idmap(void);
void template_mount_notify(void);
void template_mount_setopt(void);
void template_mount_getopt(void);
void template_mount_change_opt(void);
void template_mount_get_tree(void);
void template_mount_move_tree(void);
void template_mount_attach_tree(void);
void template_mount_detach_tree(void);
void template_mount_clone_tree(void);
void template_mount_change_tree(void);
void template_mount_set_group(void);
void template_mount_get_group(void);
void template_mount_list_group(void);
void template_mount_set_peer(void);
void template_mount_get_peer(void);
void template_mount_list_peer(void);
void template_mount_set_attr(void);
void template_mount_get_attr(void);
void template_mount_list_attr(void);
void template_mount_set_flag(void);
void template_mount_get_flag(void);
void template_mount_list_flag(void);