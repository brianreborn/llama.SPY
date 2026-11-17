#pragma once
// Small POSIX helpers shared by the collector, tracers, and fetch path.
// ASCII only. No writes to a target process.

#include <cerrno>
#include <csignal>
#include <ctime>

#include <fcntl.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>

#if defined(__linux__)
#  include <sys/prctl.h>
#endif
#if defined(__FreeBSD__) || defined(LLAMASPY_FREEBSD)
#  include <sys/procctl.h>
#endif

namespace llamaspy {

inline int PipeCloexec(int fds[2]) {
#if defined(__linux__) || defined(__FreeBSD__) || defined(LLAMASPY_FREEBSD)
  return ::pipe2(fds, O_CLOEXEC);
#else
  if (::pipe(fds) != 0) return -1;
  ::fcntl(fds[0], F_SETFD, FD_CLOEXEC);
  ::fcntl(fds[1], F_SETFD, FD_CLOEXEC);
  return 0;
#endif
}

// Ask the kernel to signal us when our parent exits, then re-check.
// expected_ppid is the parent's pid captured before fork. If that process
// is already gone, _exit so we do not keep a listen socket or a tracer.
inline void ArmParentDeath(int sig, pid_t expected_ppid) {
#if defined(__linux__)
  ::prctl(PR_SET_PDEATHSIG, sig);
#elif defined(__FreeBSD__) || defined(LLAMASPY_FREEBSD)
  ::procctl(P_PID, 0, PROC_PDEATHSIG_CTL, &sig);
#else
  (void)sig;
#endif
  if (expected_ppid > 0 && ::getppid() != expected_ppid) _exit(1);
}

// Polite signal, bounded wait, then SIGKILL. Also signals the child's
// process group when it is a group leader (setpgid(0,0) in the tracer).
inline void ReapChild(pid_t child, int polite_sig) {
  if (child <= 0) return;
  ::kill(child, polite_sig);
  ::kill(-child, polite_sig);
  for (int i = 0; i < 30; ++i) {
    int st = 0;
    pid_t r = ::waitpid(child, &st, WNOHANG);
    if (r == child || (r < 0 && errno == ECHILD)) return;
    if (r < 0 && errno == EINTR) continue;
    timespec ts{};
    ts.tv_nsec = 100000000L;
    ::nanosleep(&ts, nullptr);
  }
  ::kill(child, SIGKILL);
  ::kill(-child, SIGKILL);
  for (;;) {
    int st = 0;
    pid_t r = ::waitpid(child, &st, 0);
    if (r == child || (r < 0 && errno != EINTR)) return;
  }
}

}  // namespace llamaspy
