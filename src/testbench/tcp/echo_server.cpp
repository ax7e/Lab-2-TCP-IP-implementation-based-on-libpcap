//
// Created by Chengke on 2019/10/22.
// Modified by Chengke on 2021/08/26.
//

#include "unp.h"
#include "src/tcp/socket.h"

void str_echo(int sockfd, int sleep_) {
  ssize_t n;
  char buf[MAXLINE];
  size_t acc = 0;
  again:
  while ((n = read(sockfd, buf, MAXLINE)) > 0) {
    writen(sockfd, buf, n);
    acc += n;
    printf("\e[31m%zu\e[0m ", acc);
    fflush(stdout);
    if (sleep_) {
      sleep(1);
    }
    if (acc>18000) exit(-1);
  }
  printf("all: %zu\n", acc);
  if (n < 0 && errno == EINTR) {
    goto again;
  } else if (n < 0) {
    printf("str_echo: read error\n");
  }
  close(sockfd);
}

int main(int argc, char *argv[]) {
  struct sockaddr_in cliaddr, servaddr;
  int listenfd = Socket(AF_INET, SOCK_STREAM, 0);
  int connfd;
  int loop;
  
  bzero(&servaddr, sizeof(servaddr));
  servaddr.sin_family = AF_INET;
  servaddr.sin_addr.s_addr = htonl(INADDR_ANY);
  servaddr.sin_port = htons(10086);

  Bind(listenfd, (struct sockaddr *) &servaddr, sizeof(servaddr));
  Listen(listenfd, SOMAXCONN);

  for (loop = 0; loop < 3; loop++) {
    socklen_t clilen = sizeof(cliaddr);
    connfd = Accept(listenfd, (struct sockaddr *) &cliaddr, &clilen);
    printf("new connection\n");
    str_echo(connfd, loop==1);
  }
  return 0;
}
