#include <stdio.h>
#include <stdarg.h>
#include <string.h>
#include <pthread.h>
#include <stdlib.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <unistd.h>
#include <errno.h>
#include <signal.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <stdbool.h>
#include <time.h>

#define err_exit(msg) \
    do { \
        perror(msg); \
        exit(EXIT_FAILURE); \
    } while(0)

#define err_handle(msg, label) \
    do { \
        perror(msg); \
        goto label; \
    } while(0)

#define PORT 8080
#define MAX_BACKLOG 50
#define BUF_SIZE 1024
#define CRLF "\r\n"

typedef struct str_buf {
  char *val;
  size_t capacity; /* the allocated size */
  size_t size;     /* the already used size */
} Sb;
static int sb_init(Sb *buf, unsigned cap_bits);
static int sb_empty(Sb *buf);
static int sb_parse_http_req_header(Sb *buf);
static int sb_gen_http_res(Sb *res, Sb *req);
static int sb_putc(Sb *buf, char c);
static int sb_putn(Sb *buf, char *src, size_t n);
static int sb_puts(Sb *buf, char *src);
static char *sb_flush(Sb *buf);

typedef struct http_hdr {
    Sb hdr_sb;
} HTTPHdr;

typedef struct http_pyld {
    Sb pyld_sb;
} HTTPPyld;

typedef void (*http_method)(HTTPHdr *hdr, HTTPPyld *pyld);
typedef void (*http_parser)(const char *msg);

typedef struct http_msg {
    HTTPHdr hdr;
    HTTPPyld pyld;
    Sb strbuf;    // for receiving request and parse them into hdr and pyld
    http_method get;
    http_method post;
    http_parser parse;
} HTTPMsg;

static void conn_handler(int connfd);

int main(){
    int listenfd = socket(AF_INET, SOCK_STREAM, 0);
    int connfd;
    if(listenfd == -1)
        err_exit("socket");   

    signal(SIGCHLD, SIG_IGN); // ignore child signal

    struct sockaddr_in sv_addr;
    memset(&sv_addr, 0, sizeof sv_addr);
    sv_addr.sin_family = AF_INET;
    sv_addr.sin_addr.s_addr = htonl(INADDR_ANY);
    sv_addr.sin_port = htons(PORT);

    if(bind(listenfd, (struct sockaddr *) &sv_addr, sizeof sv_addr) == -1)
        err_exit("bind");

    if(listen(listenfd, MAX_BACKLOG) == -1)
        err_exit("listen");

    printf("Listening on port %d...\n", PORT);

    while(1){
    next:
        connfd = accept(listenfd, NULL, NULL); // blocking until new connection
        if(connfd == -1)
            err_handle("accept", next);

        again:
        switch(fork()){
            case -1: // error
                err_handle("fork", again);

            case 0:
                close(listenfd); // unnecessary fd
                conn_handler(connfd);
                exit(0);

            default: // parent
                break; // goto accept another connection
        }
    }

    // should not reach here!
    exit(1);
}

static void http_get_handler(HTTPHdr *hdr, HTTPPyld *pyld){

}

static void http_post_handler(HTTPHdr *hdr, HTTPPyld *pyld){

}

static void conn_handler(int connfd){
    Sb buf;
    sb_init(&buf, 5);

    int fd = open("./public/index.html", O_RDONLY);
    struct stat sb;
    fstat(fd, &sb);
    char cont[sb.st_size];
    read(fd, cont, sb.st_size);

    sb_puts(&buf, "HTTP/1.1 200 OK");
    sb_putn(&buf, CRLF, 2);
    sb_puts(&buf, "Content-Type: text/html; charset=utf-8");
    sb_putn(&buf, CRLF, 2);
    sb_puts(&buf, "Content-Length: 105");
    sb_putn(&buf, CRLF, 2);
    sb_puts(&buf, "Date: Sat, 18 Feb 2017 00:01:57 GMT");
    sb_putn(&buf, CRLF, 2);
    sb_puts(&buf, "Server: cool ming server");
    sb_putn(&buf, CRLF, 2);
    sb_puts(&buf, "Connection: close");
    sb_putn(&buf, CRLF, 2);
    sb_putn(&buf, CRLF, 2);
    sb_putn(&buf, cont, sb.st_size);

    send(connfd, sb_flush(&buf), buf.size, 0);

    close(connfd);
}

static int sb_init(Sb *buf, unsigned cap_bits){
  const size_t capacity = 1u << cap_bits;
again:
  buf->val = malloc(capacity);
  if(!buf->val) 
    err_handle("sb_init", again);
  *(buf->val) = 0;
  buf->capacity = capacity;
  buf->size = 0;
  return 0;
}

static int sb_putc(Sb *buf, char c){
  void *tmp;
  if(buf->size == buf->capacity){
    const size_t new_capacity = buf->capacity << 1u;
again:
    tmp = realloc(buf->val, new_capacity);
    if(!tmp)
        err_handle("sb_putc", again);
    buf->val = tmp;
    buf->capacity = new_capacity;
  }
  buf->val[buf->size++] = c;
  return 0;
}

static int sb_putn(Sb *buf, char *src, size_t n){
  const size_t capacity = buf->capacity;
  const size_t size = buf->size;
  const size_t balance = capacity - size;
  const size_t extra_need = (balance < n) ? (n - balance) : 0;
  void *tmp;

  if(extra_need > 0){
    const size_t total_need = capacity + extra_need;
    size_t new_capacity = capacity;
    do
      new_capacity <<= 1;
    while(new_capacity < total_need);

again:
    tmp = realloc(buf->val, new_capacity);
    if(!tmp) 
        err_handle("sb_putn", again);
    buf->val = tmp;
    buf->capacity = new_capacity;
  }

  memcpy(buf->val + size, src, n);
  buf->size += n;
  return 0;
}

static int sb_puts(Sb *buf, char *src){
  sb_putn(buf, src, strlen(src));
}

static char *sb_flush(Sb *buf){
  char *ret;
  size_t size = buf->size;

  if(0 == buf->size || buf->val[buf->size - 1] != '\0'){
    sb_putc(buf, '\0');
    size++;
  }

again:
  ret = strdup(realloc(buf->val, size)); /* using strdup since realloc may remain the same region of memory */
  if(!ret)
    err_handle("sb_flush", again);

  free(buf->val);
  return ret;
}

static int sb_empty(Sb *buf){
    *(buf->val) = '\0';
    buf->size = 0;
    return 0;
}