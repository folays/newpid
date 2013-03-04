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
static int flag_daemon;
static int flag_foreground;
static int flag_kill;
static int flag_pty = 0; /* 1 == pty, -1 == nopty, 0 == default */

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

int daemon_main(void *arg)
{
  int listen_fd;
  struct sockaddr_un address;

#ifdef FLEX_MNT
  if (mount("none", "/proc", "proc", MS_NOSUID | MS_NODEV | MS_NOEXEC | MS_RELATIME, NULL))
    err(1, "could not mount /proc");
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

      printf("POLL\n");

      if (fds[0].events & POLLIN)
	{
	  struct sockaddr address;
	  socklen_t address_length;
	  int connection_fd;

	  if ((connection_fd = accept(listen_fd, &address, &address_length)) >= 0)
	    {
	      printf("ACCEPT RETURN %d\n", connection_fd);
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
      {
	int waited;

	while (waited = waitpid(-1, NULL, WNOHANG))
	  ;
      }
    }
}

int child_main(int fd)
{
  int amaster;
  char name[256];

  pid_t pid_slave = forkpty(&amaster, NULL, NULL, NULL);
  if (pid_slave == -1)
    err(1, "forkpty");

  if (pid_slave == 0)
    {
      close(fd);
      chdir("/");
      execlp("bash", "bash", NULL);
      err(1, "execlp");
    }

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
	      char buf[255];

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

  {"dev", required_argument, NULL, 'd'},
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
	}
    }
  return 0;
}

static void usage()
{
  printf("usage: [--daemon] NAME\n");
  exit(1);
}

static void client_try_connect(int argc, char **argv)
{
  int fd;
  char *fd_str;

  if ((fd = _client_get_connect_fd()) < 0)
    err(1, "could not connect to daemon");

  if (asprintf(&fd_str, "FD:%d", fd) < 0)
    err(1, "asnprintf");

  execlp("socat", "socat", "-,echo=0,raw", fd_str, NULL);
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
    client_try_create();

  if (flag_kill)
    client_try_kill();

  if (argc > 0)
    {
      printf("TRY CONNECT\n");
      client_try_connect(argc, argv);
    }

  exit(0);
}