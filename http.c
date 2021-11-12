#define _GNU_SOURCE
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

#define PORT 80
#define MAX_BACKLOG 50
#define BUF_SIZE 1024
#define CRLF "\r\n"

typedef struct str_buf {
  char *val;
  size_t capacity; /* the allocated size */
  size_t size;     /* the already used size */
} Sb;
static int sb_init(Sb *buf, unsigned cap_bits);
static int sb_clear(Sb *buf);
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

typedef struct http_msg {
    HTTPHdr hdr;
    HTTPPyld pyld;
} HTTPMsg;

static void httpmsg_parse(HTTPMsg *msg, const char *buf);
static void http_get_handler(int connfd, HTTPMsg *msg);
static void http_post_handler(int connfd, HTTPMsg *msg);
static void signup(HTTPMsg *msg); // redirect to login page
static void login(HTTPMsg *msg); // redirect to index page
static char *get_content_type(char *req_tgt);

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

            case 0: // child
                close(listenfd); // unnecessary fd
                conn_handler(connfd);
                exit(0);

            default: // parent
                close(connfd); // unnecessary fd
                break;
        }
    }

    // should not reach here!
    exit(1);
}

static void conn_handler(int connfd){
    char tmp_buf[BUF_SIZE];
    memset(tmp_buf, 0, sizeof(char[BUF_SIZE]));

    HTTPMsg msg;
    sb_init(&msg.hdr.hdr_sb, 5);
    sb_init(&msg.pyld.pyld_sb, 5);

    ssize_t recv_size;
    long content_len = -1;
    char *ptr, *qtr;
    _Bool is_get = false;     // only support get and post method
    while(1){
    next:
        // get header
        recv_size = recv(connfd, tmp_buf, BUF_SIZE, 0);
        is_get = (tmp_buf[0] == 'G' ? true : false);
        while(!strstr(tmp_buf, CRLF CRLF)){
        again:
            if(recv_size <= 0){
                if(recv_size == -1)
                    err_handle("recv header", again);
                if(recv_size == 0){            // peer socket shutdown early
                    sb_clear(&msg.hdr.hdr_sb);
                    goto next;
                }
            }
            sb_puts(&msg.hdr.hdr_sb, tmp_buf);
            if((ptr = strstr(tmp_buf, "Content-Length")) && 
                (qtr = strstr(ptr, CRLF))){     // fixme: if the content length and CRLF are cut
                content_len = strtol(ptr, NULL, 10);
            }
            recv_size = recv(connfd, tmp_buf, BUF_SIZE, 0);
        }

        sb_puts(&msg.hdr.hdr_sb, tmp_buf); // header last line which includes CRLF CRLF

        // get payload
        if(content_len != -1 && content_len != 0){
            char tbuf[content_len + 1];
            memset(tbuf, 0, sizeof(char[content_len + 1]));
        pyldagain:
            recv_size = recv(connfd, tbuf, content_len, 0);
            if(recv_size <= 0){
                if(recv_size == -1)
                    err_handle("recv payload", pyldagain);
                if(recv_size == 0){            // peer socket shutdown early
                    sb_clear(&msg.pyld.pyld_sb);
                    goto next;
                }
            }

            sb_puts(&msg.pyld.pyld_sb, tbuf);
        }

        if(is_get)
            http_get_handler(connfd, &msg);
        else
            http_post_handler(connfd, &msg);
    }
    close(connfd);
}

static void httpmsg_parse(HTTPMsg *msg, const char *buf){

}

static void http_get_handler(int connfd, HTTPMsg *msg){
    char buf[BUF_SIZE];
    memset(buf, 0, sizeof(char[BUF_SIZE]));
    ssize_t send_size;

    // get request target
    Sb req_tgt_path_buf;
    sb_init(&req_tgt_path_buf, 5);
    sb_putc(&req_tgt_path_buf, '.');
    char *ptr = strstr(msg->hdr.hdr_sb.val, "/");
    char *qtr = strstr(ptr, " "); 
    sb_putn(&req_tgt_path_buf, ptr, qtr - ptr);

    char *req_tgt_path = sb_flush(&req_tgt_path_buf);
    int req_tgt_fd = open(req_tgt_path, O_RDONLY);
    int _404_fd;

    struct stat req_tgt_stat;
    char time_buf[100];
    strftime(time_buf, 100, "%a %b %d %T %Y", localtime(&(time_t){time(NULL)}));
    Sb res_hdr_buf;
    sb_init(&res_hdr_buf, 5);
    char *res_hdr;
    if(req_tgt_fd == -1){ // 404 not found
        // build response header
        sb_puts(&res_hdr_buf, "HTTP/1.1 404 Not Found");
        sb_puts(&res_hdr_buf, CRLF);

        sb_puts(&res_hdr_buf, "Content-Type: text/html; charset=utf-8");
        sb_puts(&res_hdr_buf, CRLF);

        sb_puts(&res_hdr_buf, "Date: ");
        sb_puts(&res_hdr_buf, time_buf);
        sb_puts(&res_hdr_buf, CRLF);

        sb_puts(&res_hdr_buf, "Server: ming cool server");
        sb_puts(&res_hdr_buf, CRLF);

    openagain:
       _404_fd = open("./404.html", O_RDONLY);
       if(_404_fd == -1)
            err_handle("open", openagain);
       fstat(_404_fd, &req_tgt_stat);
       sprintf(buf, "%ld", req_tgt_stat.st_size);
       sb_puts(&res_hdr_buf, "Content-Length: ");
       sb_puts(&res_hdr_buf, buf);
       sb_puts(&res_hdr_buf, CRLF);
       sb_puts(&res_hdr_buf, CRLF);

        res_hdr = sb_flush(&res_hdr_buf);
    notfound:
        send_size = send(connfd, res_hdr, res_hdr_buf.size, 0);
        if(send_size == -1)
            err_handle("send response header(404)", notfound);

        // send response payload
        while(read(_404_fd, buf, BUF_SIZE) > 0){
        send404again:
            send_size = send(connfd, buf, BUF_SIZE, 0);
            if(send_size == -1)
                err_handle("send response payload(404)", send404again);
        }
        close(_404_fd);
    } else { // found
        // build response header
        sb_puts(&res_hdr_buf, "HTTP/1.1 200 OK");
        sb_puts(&res_hdr_buf, CRLF);

        sb_puts(&res_hdr_buf, "Date: ");
        sb_puts(&res_hdr_buf, time_buf);
        sb_puts(&res_hdr_buf, CRLF);

        sb_puts(&res_hdr_buf, "Server: ming cool server");
        sb_puts(&res_hdr_buf, CRLF);

        char *ctt = get_content_type(req_tgt_path);
        sb_puts(&res_hdr_buf, ctt);
        sb_puts(&res_hdr_buf, CRLF);
        free(ctt);

        fstat(req_tgt_fd, &req_tgt_stat);
        sprintf(buf, "%ld", req_tgt_stat.st_size);
        sb_puts(&res_hdr_buf, "Content-Length: ");
        sb_puts(&res_hdr_buf, buf);
        sb_puts(&res_hdr_buf, CRLF);
        sb_puts(&res_hdr_buf, CRLF);

        res_hdr = sb_flush(&res_hdr_buf);
    found:
        send_size = send(connfd, res_hdr, res_hdr_buf.size, 0);
        if(send_size == -1)
            err_handle("send response header(found)", found);

        // send response payload
        while(read(req_tgt_fd, buf, BUF_SIZE) > 0){
        sendreqtgtagain:
            send_size = send(connfd, buf, BUF_SIZE, 0);
            if(send_size == -1)
                err_handle("send response payload(found)", sendreqtgtagain);
        }
        close(req_tgt_fd);
    }
eof:
    send_size = send(connfd, CRLF, 2, 0);
    if(send_size == -1)
        err_handle("send CRLF", eof);

end:
    free(res_hdr);
    free(req_tgt_path);
    return;
}

static void signup(HTTPMsg *msg){

}

static void login(HTTPMsg *msg){

}

static void http_post_handler(int connfd, HTTPMsg *msg){
    if(strstr(msg->hdr.hdr_sb.val, "login")){
        login(msg);
    } else if(strstr(msg->hdr.hdr_sb.val, "register")){
        signup(msg);
    } else { // upload 

    }
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

static int sb_clear(Sb *buf){
    *(buf->val) = '\0';
    buf->size = 0;
    return 0;
}

static char *get_content_type(char *req_tgt){
    Sb buf;
    sb_init(&buf, 5);
    if(strstr(req_tgt, ".jpg") || strstr(req_tgt, ".png") || strstr(req_tgt, ".jpeg"))
        sb_puts(&buf, "Content-Type: image/jpg");
    else if(strstr(req_tgt, ".gif"))
        sb_puts(&buf, "Content-Type: image/gif");
    else 
        sb_puts(&buf, "Content-Type: text/html; charset=utf-8");

    return sb_flush(&buf);
}