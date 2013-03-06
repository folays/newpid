#define _GNU_SOURCE
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <sys/mman.h>
#include <sched.h>
#include <signal.h>

#include <getopt.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <sys/un.h>
#include <unistd.h>
#include <sys/mount.h>
#include <pty.h>
#include <fcntl.h>
#include <poll.h>

#define STACK_SIZE (1 * 1024 * 1024)

#define FLEX_PID 1 /* do we unshare the PID namespace ? */
#define FLEX_MNT 1 /* do we unshare the mount namespace ? */

static char *gl_name;
static char *gl_chroot_path;
static int flag_daemon;
static int flag_foreground;
static int flag_kill;
static int flag_pty = 0; /* 1 == pty, -1 == nopty, 0 == default */
static int flag_chroot;
static int flag_chroot_always;

static int _create_socket(struct sockaddr_un *address)
{
  int fd;

  if ((fd = socket(PF_UNIX, SOCK_STREAM, 0)) >= 0)
    {
      memset(address, '\0', sizeof(*address));
      address->sun_family = AF_UNIX;
      snprintf(address->sun_path, sizeof(address->sun_path), "%s", gl_name);
    }
  return fd;
}

static void _daemon_replace_proc(const char *path)
{
  /* XXX: umount() of the old proc path doesn't always works, because sometimes
   * there is multiple filesystems mounted below /proc... like this one:
   * - binfmt_misc on /proc/sys/fs/binfmt_misc type binfmt_misc (rw,noexec,nosuid,nodev)
   */
  if (umount(path) && !(errno == EINVAL || errno == EBUSY))
    err(1, "could not umount %s", path);
  if (mount("none", path, "proc", MS_NOSUID | MS_NODEV | MS_NOEXEC | MS_RELATIME, NULL))
    err(1, "could not mount %s", path);

}

int daemon_main(void *arg)
{
  int listen_fd;
  struct sockaddr_un address;

  {
    int fd_null;

    if ((fd_null = open("/dev/null", O_RDWR)) < 0)
      err(1, "could not open /dev/null");
    dup2(fd_null, 0);
    dup2(fd_null, 1);  
    dup2(fd_null, 2);
    close(fd_null);
  }

#ifdef FLEX_MNT
  _daemon_replace_proc("/proc");
  if (gl_chroot_path)
    {
      char *path;

      if (asprintf(&path, "%s/proc", gl_chroot_path) < 0)
	err(1, "could not asprintf");
      _daemon_replace_proc(path);
    }
#endif /* !FLEX_MNT */

  unlink(gl_name);
  if ((listen_fd = _create_socket(&address)) < 0)
    err(1, "could not create socket");
  if (bind(listen_fd, (struct sockaddr *)&address, sizeof(address)) != 0)
    err(1, "bind");
  if (listen(listen_fd, 5))
    err(1, "listen");

  if (chmod(gl_name, 0666) < 0)
    err(1, "chmod");

  signal(SIGCHLD, SIG_IGN);

  daemon_loop(listen_fd);
}

int daemon_loop(int listen_fd)
{
  struct pollfd fds[1];
  int nfds = 0;

  fds[nfds++] = (struct pollfd){.fd = listen_fd, .events = POLLIN};

  while (1)
    {
      poll(fds, nfds, -1);

      if (fds[0].events & POLLIN)
	{
	  struct sockaddr address;
	  socklen_t address_length;
	  int connection_fd;

	  if ((connection_fd = accept(listen_fd, &address, &address_length)) >= 0)
	    {
	      int child_pid = fork();
	      if (child_pid == -1)
		err(1, "fork");
	      if (child_pid)
		{
		  close(connection_fd);
		}
	      else
		{
		  close(listen_fd);
		  child_main(connection_fd);
		}
	    }
	}
    }
}

int _child_getint(int fd)
{
  int n;

  if (read(fd, &n, sizeof(n)) < 0)
    err(1, "read");
  return ntohl(n);
}

unsigned char *_child_getstr(int fd, int len)
{
  unsigned char *s, *pos;

  if (!(s = malloc(len + 1)))
    err(1, "malloc");

  pos = s;
  while (len)
    {
      int nb;

      nb = read(fd, pos, len);
      if (nb < 0)
	err(1, "read");
      pos += nb;
      len -= nb;
    }
  *pos = '\0';
  return s;
}

int child_main(int fd)
{
  int option_tty;
  int option_chroot;
  struct winsize ws;
  int argc;
  char **argv;
  int amaster;

  {
    int i;

    option_tty = _child_getint(fd);
    /* printf("TTY : %d\n", option_tty); */
    option_chroot = _child_getint(fd);
    /* printf("CHROOT : %d\n", option_chroot); */
    ws.ws_row = _child_getint(fd);
    ws.ws_col = _child_getint(fd);
    argc = _child_getint(fd);
    /* printf("ARGC : %d\n", argc); */
    if (argc > 1000)
      errx(1, "argc too many arguments... (%d)", argc);
    if (!(argv = malloc((argc + 1) * sizeof(*argv))))
      err(1, "malloc");
    for (i = 0; i < argc; ++i)
      {
	int len = _child_getint(fd);
	/* printf("ARGV[%d] : length %d\n", i, len); */
	if (len > 4096)
	  errx(1, "argument too long... (%d)", len);
	argv[i] = _child_getstr(fd, len);
	/* printf("ARGV[%d] : %.*s\n", i, len, argv[i]); */
      }
    argv[argc] = NULL;
  }

  pid_t pid_slave = forkpty(&amaster, NULL, NULL, NULL);
  if (pid_slave == -1)
    err(1, "forkpty");

  if (pid_slave == 0)
    {
      /* TTY slave */
      close(fd);
      if (gl_chroot_path && (flag_chroot_always || option_chroot))
	{
	  if (chroot(gl_chroot_path))
	    err(1, "chroot");
	}
      if (chdir("/"))
	err(1, "chdir");
      execvp(argv[0], argv);
      err(1, "execvp");
    }

  /* PTY master starting from here... */
  ioctl(amaster, TIOCSWINSZ, &ws);

  struct pollfd fds[2];
  int nfds = 0;

  fds[nfds++] = (struct pollfd){.fd = fd, .events = POLLIN};
  fds[nfds++] = (struct pollfd){.fd = amaster, .events = POLLIN};
  while (1)
    {
      int i;

      /* printf("poll...\n"); */
      int nb_changed = poll(fds, nfds, -1);
      /* printf("poll nb_changes : %d\n", nb_changed); */

      for (i = 0; i < nfds; ++i)
	{
	  if (fds[i].revents & POLLIN)
	    {
	      char buf[4096];

	      /* printf("POLLIN on %d\n", i); */
	      int ret = read(fds[i].fd, buf, sizeof(buf));
	      /* printf("READ %d\n", ret); */
	      if (ret < 0)
		{
		  warn("read error");
		  /* fds[i].events &= ~POLLIN; */
		}
	      else
		write(fds[i].fd == fd ? amaster : fd, buf, ret);
	    }
	  if (fds[i].revents & POLLHUP)
	    {
	      {
		close(fds[i].fd == fd ? amaster : fd);
		close(fds[i].fd);
		exit(0);
	      }
	      /* printf("POLLHUP on %d\n", i); */
	      memcpy(&fds[i], &fds[nfds - 1], sizeof(*fds));
	      --nfds;
	      continue;
	    }
	}
    }
}

static int _client_get_connect_fd()
{
  int fd;
  struct sockaddr_un address;

  if ((fd = _create_socket(&address)) < 0)
    err(1, "could not create a socket");

  if (connect(fd, &address, sizeof(address)) != 0)
    {
      if (errno != ENOENT && errno != ECONNREFUSED)
	err(1, "could not connect to %s", gl_name);
      return -1;
    }

  return fd;
}

static int client_try_kill()
{
  int fd;
  struct ucred credentials;
  int ucred_length = sizeof(credentials);

  if ((fd = _client_get_connect_fd()) < 0)
    err(1, "could not connect to daemon");

  if (getsockopt(fd, SOL_SOCKET, SO_PEERCRED, &credentials, &ucred_length))
    err(1, "getsockopt");

  close(fd);

  if (kill(credentials.pid, SIGKILL) < 0)
    err(1, "could not kill");

  return 0;
}

static int pid_init = -1; /* used only by the SIGINT handler */

static void do_kill()
{
  if (pid_init != -1)
    {
      if (kill(pid_init, SIGKILL))
	err(1, "kill");
      pid_init = -1;
    }
}

void handler_sig_int(int sig)
{
  do_kill();
}

static void client_try_create()
{
  void *stack = mmap(NULL, STACK_SIZE, PROT_READ | PROT_WRITE | PROT_EXEC,
		     MAP_PRIVATE | MAP_ANONYMOUS | MAP_GROWSDOWN, -1, 0);
  if (stack == MAP_FAILED)
    err(1, "could not mmap");

  pid_init = clone(daemon_main, stack + STACK_SIZE, 0 |
#ifdef FLEX_PID
		   CLONE_NEWPID |
#endif /* !FLEX_PID */
#ifdef FLEX_MNT
		   CLONE_NEWNS |
#endif /* !FLEX_MNT */
		   SIGCHLD, NULL);

  if (pid_init <= 0)
    err(1, "could not clone");

  if (flag_foreground)
    {
      struct sigaction sigact = {.sa_handler = handler_sig_int};
      sigaction(SIGINT, &sigact, NULL);

      int waited = waitpid(pid_init, NULL, 0);
      if (waited == -1)
	err(1, "waitpid");
      do_kill();
    }
}

static struct option long_options[] = {
  {"daemon", no_argument, NULL, 'd'},
  {"foreground", no_argument, NULL, 'f'},
  {"kill", no_argument, NULL, 'k'},
  {"chroot", optional_argument, NULL, 'c'},
  {NULL, 0, NULL, 0},
};

static int main_getopt(int argc, char **argv)
{
  int opt;

  while ((opt = getopt_long(argc, argv, "", long_options, NULL)) != -1)
    {
      switch (opt)
	{
	case 'd':
	  flag_daemon = 1;
	  break;
	case 'f':
	  flag_foreground = 1;
	  break;
	case 'k':
	  flag_kill = 1;
	  break;
	case 't':
	  flag_pty = 1;
	  break;
	case 'T':
	  flag_pty = -1;
	  break;
	case 'c':
	  flag_chroot = 1;
	  if (optarg)
	    {
	      if (*optarg == ':')
		{
		  flag_chroot_always = 1;
		  optarg++;
		}
	      gl_chroot_path = strdup(optarg);
	    }
	  break;
	}
    }
  return 0;
}

static void usage()
{
  printf("usage: [--daemon] NAME\n");
  exit(1);
}

static void _client_putint(int fd, int n)
{
  n = htonl(n);

  if (write(fd, &n, sizeof(n)) < 0)
    err(1, "write");
}

static void client_try_connect(int argc, char **argv)
{
  int fd;
  char *fd_str;

  if ((fd = _client_get_connect_fd()) < 0)
    err(1, "could not connect to daemon");

  if (flag_pty == 0)
    {
      if (!isatty(0))
	flag_pty = -1;
      else
	{
	  flag_pty = argc ? -1 : 1;
	}
    }

  _client_putint(fd, flag_pty == 1 ? 1 : 0); /* put flag_tty */
  _client_putint(fd, flag_chroot == 1 ? 1 : 0); /* put flag_chroot */

  {
    struct winsize ws;

    if (ioctl(0, TIOCGWINSZ, &ws))
      ws = (struct winsize){.ws_row = 50, .ws_col = 240}; /* sane default relative to MY environment :p */
    _client_putint(fd, ws.ws_row);
    _client_putint(fd, ws.ws_col);
  }

  if (!argc)
    {
      char *command = "bash";

      _client_putint(fd, 1);
      _client_putint(fd, strlen(command));
      if (write(fd, command, strlen(command)) < 0)
	err(1, "write");
    }
  else
    {
      int i;

      _client_putint(fd, argc); /* put argc */
      for (i = 0; i < argc; ++i)
	{
	  /* put (strlen, argv) tuple for each argv[] */
	  _client_putint(fd, strlen(argv[i]));
	  if (write(fd, argv[i], strlen(argv[i])) < 0)
	    err(1, "write");
	}
    }

  if (asprintf(&fd_str, "FD:%d", fd) < 0)
    err(1, "asnprintf");

  if (isatty(0))
    execlp("socat", "socat", "-,echo=0,raw", fd_str, NULL);
  else
    execlp("socat", "socat", "-", fd_str, NULL);
  err(1, "could not exec socat");
}

int main(int argc, char **argv)
{
  if (main_getopt(argc, argv))
    usage();

  argc -= optind;
  argv += optind;

  if (argc < 1)
    usage();

  if (asprintf(&gl_name, "/var/run/newpid.%s", argv[0]) < 0)
    err(1, "could not asprintf");
  --argc;
  ++argv;

  if (flag_daemon)
    {
      int fd;

      if ((fd = _client_get_connect_fd()) >= 0)
	{
	  close(fd);
	}
      else
	client_try_create();
    }

  if (flag_kill)
    client_try_kill();

  if (!flag_daemon)
    {
      client_try_connect(argc, argv);
    }

  exit(0);
}
