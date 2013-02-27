#define _GNU_SOURCE
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <sys/mman.h>
#include <sched.h>
#include <signal.h>

#include <sys/socket.h>
#include <sys/un.h>
#include <unistd.h>
#include <pty.h>
#include <fcntl.h>
#include <poll.h>

#define STACK_SIZE (1 * 1024 * 1024)

#define FLEX_PID 1
#define FLEX_MNT 1

int child_main(void *arg)
{
  struct sockaddr_un address;
  int socket_fd;
  int connection_fd;
  socklen_t address_length;

  printf("NEW CHILD %d\n", getpid());
#ifdef FLEX_MNT
  system("mount -n -t proc none /proc");
#endif /* !FLEX_MNT */
  /* system("ps auxf"); */

  printf("SOCKET ! \n");

  socket_fd = socket(PF_UNIX, SOCK_STREAM, 0);

  unlink("/var/run/newpid");

  memset(&address, '\0', sizeof(address));
  address.sun_family = AF_UNIX;
  snprintf(address.sun_path, sizeof(address.sun_path), "/var/run/newpid");
  printf("WILL2\n");
  if (bind(socket_fd, (struct sockaddr *)&address, sizeof(address)) != 0)
    err(1, "bind");
  printf("WILL1\n");
  if (listen(socket_fd, 5))
    err(1, "listen");

  if (chmod("/var/run/newpid", 0666) < 0)
    err(1, "chmod");

  printf("accept loop\n");

  while ((connection_fd = accept(socket_fd, (struct sockaddr *)&address, &address_length)) >= 0)
    {
      printf("accepted!\n");
      int child_pid = fork();
      if (child_pid == -1)
	err(1, "fork");
      if (child_pid)
	{
	  close(connection_fd);
	}
      else
	{
	  close(socket_fd);
	  do_child_stuff(connection_fd);
	}
    }
}

int do_child_stuff(int fd)
{
  int amaster;
  char name[256];

  write(fd, "coucou\n", 7);

  /* sleep(3); */
  printf("OPENPTY...\n");
  pid_t pid_slave = forkpty(&amaster, NULL, NULL, NULL);
  if (pid_slave == -1)
    err(1, "forkpty");
  printf("OPENPTY DONE (%d)\n", pid_slave);

  if (pid_slave == 0)
    {
      close(fd);
      write(1, "SLAVE\n", 6);
      execlp("cat", "cat", NULL);
      err(1, "execlp");
    }

  write(fd, "coucou poll\n", 12);

  struct pollfd fds[2];

  /* if (fcntl(fd, F_SETFL, fcntl(fd, F_GETFL) | O_NONBLOCK) < 0) */
  /*   err(1, "fcntl error"); */
  /* if (fcntl(amaster, F_SETFL, fcntl(amaster, F_GETFL) | O_NONBLOCK) < 0) */
  /*   err(1, "fcntl error"); */

  fds[0] = (struct pollfd){.fd = fd, .events = POLLIN};
  fds[1] = (struct pollfd){.fd = amaster, .events = POLLIN};
  while (1)
    {
      printf("poll...\n");
      int nb_changed = poll(fds, 2, -1);
      printf("poll nb_changes : %d\n", nb_changed);

      if (fds[0].revents & (POLLIN | POLLPRI | POLLOUT | POLLERR | POLLHUP | POLLRDHUP | POLLNVAL))
	{
	  char buf[256];

	  printf("change on 0\n");
	  int ret = read(fds[0].fd, buf, sizeof(buf));
	  printf("READ fds[0] %d\n", ret);
	  if (ret < 0)
	    {
	      warn("read on fds[0]");
	      fds[0].events &= ~POLLIN;
	    }
	  else
	    write(fds[1].fd, buf, ret);
	}
      if (fds[1].revents & (POLLIN | POLLPRI | POLLOUT | POLLERR | POLLHUP | POLLRDHUP | POLLNVAL))
	{
	  char buf[256];

	  printf("change on 1\n");
	  int ret = read(fds[1].fd, buf, sizeof(buf));
	  printf("READ fds[1] %d\n", ret);
	  if (ret < 0)
	    {
	      warn("read on fds[1]");
	      fds[1].events &= ~POLLIN;
	    }
	  else
	    write(fds[0].fd, buf, ret);
	}
    }
}

static int pid_init = -1;

static void do_kill()
{
  if (pid_init != -1)
    {
      printf("KILL INIT PID %d\n", pid_init);
      if (kill(pid_init, SIGKILL))
	err(1, "kill");
      pid_init = -1;
    }
}

void handler_sig_int(int sig)
{
  do_kill();
}

int main(int argc, char **argv)
{
  void *region = mmap(NULL, STACK_SIZE, PROT_READ | PROT_WRITE | PROT_EXEC,
		     MAP_PRIVATE | MAP_ANONYMOUS | MAP_GROWSDOWN, -1, 0);
  printf("mmap : %p\n", region);
  if (region == MAP_FAILED)
    err(1, "could not mmap");
  void *stack = region + STACK_SIZE;
  printf("stack: %p (len %ld)\n", stack, stack - region);

  printf("PARENT PID : %d\n", getpid());

  pid_init = clone(child_main, stack, 0 | 
#ifdef FLEX_PID
		   CLONE_NEWPID |
#endif /* !FLEX_PID */
#ifdef FLEX_MNT
		   CLONE_NEWNS |
#endif /* !FLEX_MNT */
		   SIGCHLD, NULL);
  if (pid_init <= 0)
    err(1, "could not clone");
  printf("CLONED ! %d\n", pid_init);

  struct sigaction sigact = {.sa_handler = handler_sig_int};
  sigaction(SIGINT, &sigact, NULL);

  int waited = waitpid(pid_init, NULL, 0);
  printf("WAITPID returned %d\n", waited);
  if (waited == -1)
    err(1, "waitpid");
  do_kill();
  printf("exit\n");
}
