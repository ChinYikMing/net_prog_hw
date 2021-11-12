#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <signal.h>
#include <sys/sendfile.h>
 
int main() {
    int fd;
    unsigned val = 1;
    struct sockaddr_in sin;
    fd = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &val, sizeof(val));
 
    bzero(&sin, sizeof(sin));
    sin.sin_family = AF_INET;
    sin.sin_port = htons(9000);
    sin.sin_addr.s_addr = htonl(INADDR_ANY);
    if (bind(fd, (struct sockaddr*) &sin, sizeof(sin)) < 0) { 
        perror("bind"); 
        exit(-1);
    }
    if (listen(fd, SOMAXCONN) < 0) { 
        perror("listen");
        exit(-1); 
    }
    struct sockaddr_in psin;
    signal(SIGCHLD, SIG_IGN); // prevent child zombie
    while (1) {
        socklen_t s = sizeof(psin);
        int p_fd = accept(fd, (struct sockaddr*) NULL, NULL);
        fprintf(stderr, "accept!\n");
        if (p_fd < 0) {
            perror("accept");
            continue;
        }
        pid_t pid = fork();
        if (pid < 0) {
            perror("fork");
            continue;
        }
        if (pid == 0) {
            char header[] =  
                "HTTP/1.1 200 OK\r\n"
                "Content-Type: image/jpeg\r\n"
                "\r\n"
                ;
            write(p_fd, header, sizeof(header) - 1);
 
            int img_fd = open("test.jpg", O_RDONLY);
            char buf[8192];
            for (int s = 0; (s = read(img_fd, buf, 1024)) > 0; ) {
                write(p_fd, buf, s);
            }
            shutdown(p_fd, SHUT_RDWR);
            close(p_fd);
            close(img_fd);
            exit(0); 
        }
        // close(p_fd);
    }
}
