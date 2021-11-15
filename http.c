#define _GNU_SOURCE
#include <stdarg.h>
#include <stdio.h>
#include <string.h>
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
#include <libgen.h>
#include <libgen.h>
#include <dirent.h>

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
#define MAX_CONTENT_LENGTH 0x10000  // 1MB
#define BUF_SIZE 4096
#define CRLF "\r\n"

typedef struct str_buf {
  char *val;
  size_t capacity; /* the allocated size */
  size_t size;     /* the already used size */
} Sb;
static int sb_init(Sb *buf, unsigned cap_bits);
static void sb_clear(Sb *buf);
static int sb_putc(Sb *buf, char c);
static int sb_putn(Sb *buf, char *src, size_t n);
static int sb_puts(Sb *buf, char *src);
static char *sb_flush(Sb *buf);

typedef struct client_info {
    char *name;
    char *nounce;
} ClientInfo;
static void clinfo_init(ClientInfo *clinfo);
static void clinfo_destroy(ClientInfo *clinfo);

typedef struct http_msg {
    Sb buf;
    ClientInfo clinfo;
} HTTPMsg;

static _Bool http_get_handler(int connfd, HTTPMsg *msg);
static _Bool http_post_handler(int connfd, HTTPMsg *msg);
static void http_err_send(int connfd, int code, int hdr_cnt, ...);
static void http_resrc_send(int connfd, int code, char *req_tgt_path, int hdr_cnt, ...);
static void http_redirect_send(int connfd, int code, char *redirection, int hdr_cnt, ...);

static _Bool signup(HTTPMsg *msg);
static _Bool login(HTTPMsg *msg);
static _Bool file_upload(HTTPMsg *msg);
static void get_uname_psw(HTTPMsg *msg, char *uname, char *psw);
static char *get_content_type(char *req_tgt);
static char *code2msg(int code);
static char *get_cookie(HTTPMsg *msg);
static char *cookie_gen(char *username);
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

    int val = 1;
    setsockopt(listenfd, SOL_SOCKET, SO_REUSEADDR, &val, sizeof(val));

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

    // SHOULD NOT reach here!
    exit(1);
}

static void conn_handler(int connfd){
    char buf[BUF_SIZE];
    memset(buf, 0, sizeof(char[BUF_SIZE]));

    HTTPMsg msg;
    sb_init(&msg.buf, 5);
    clinfo_init(&msg.clinfo);

    char *ptr, *qtr;
    _Bool is_get = false;     // only support get and post method
    _Bool success;

    // FILE *conn_fptr = fdopen(connfd, "r");   // for recv line by line
    while(1){
    next:
        if(strstr(msg.buf.val, "login")){
            printf("in conn: %p, strlen: %zu\n", &msg, strlen(msg.clinfo.name));
        }
        sb_clear(&msg.buf);

        // get header
        while(recv(connfd, buf, BUF_SIZE, 0)){
            sb_puts(&msg.buf, buf);
            if(strstr(msg.buf.val, CRLF CRLF))  // reach double CRLF
                break;
        }

        if(strncmp(msg.buf.val, "GET", 3) == 0)
            is_get = true;
        else if(strncmp(msg.buf.val, "POST", 4) == 0)
            is_get = false;
        else { // unsupported method
            http_err_send(connfd, 405, 0);
            goto end;
        }

        if(is_get){
            success = http_get_handler(connfd, &msg);
            if(!success){
                printf("failed get!\n");
                goto end;
            }
        } else {
            success = http_post_handler(connfd, &msg);
            if(!success){
                printf("failed postt!\n");
                goto end;
            }
        }
    }
end:
    if(strstr(msg.buf.val, "login"))
        printf(" early end here\n");
    // fclose(conn_fptr);
    free(sb_flush(&msg.buf));
    clinfo_destroy(&msg.clinfo);
    close(connfd);
    return;
}

static _Bool signup(HTTPMsg *msg){
    char uname[11] = {0};
    char psw[9] = {0};
    get_uname_psw(msg, uname, psw);

    strcpy(msg->clinfo.name, "aooke");

    // check if any same username exists
    DIR *dir_user = opendir("./users/");
    struct dirent *entry_user;

    while((entry_user = readdir(dir_user))){
        if(strcmp(entry_user->d_name, uname) == 0)
            return false;
    }

    // username valid
    int direcfd = dirfd(dir_user);
    mkdirat(direcfd, uname, S_IRUSR | S_IWUSR | S_IRGRP | S_IWGRP);

    int shadowfd = open("./shadow", O_APPEND | O_WRONLY);
    char rec_new[32] = {0};
    strcpy(rec_new, uname);
    strcat(rec_new, ":");
    strcat(rec_new, psw);
    strcat(rec_new, "\n");
    write(shadowfd, rec_new, strlen(rec_new));

    close(shadowfd);
    close(direcfd);
    return true;
}

static _Bool login(HTTPMsg *msg){
    char uname[11] = {0};
    char psw[9] = {0};
    get_uname_psw(msg, uname, psw);

    char rec[32] = {0}; // post request login record
    strcpy(rec, uname);
    strcat(rec, ":");
    strcat(rec, psw);

    // check if the user exists
    char buf[32]; // record in shadow file
    size_t buf_len;
    FILE *shadow_fptr = fopen("./shadow", "r");
    while(fgets(buf, 32, shadow_fptr)){
        buf_len = strlen(buf);
        if(buf_len && buf[buf_len - 1] == '\n')
            buf[buf_len - 1] = 0; 

        if(strcmp(buf, rec) == 0){
            // msg->clinfo.name for upload file and view list of uploaded files
            strcpy((msg->clinfo).name, uname);
            // gen cookie for page protection
            char *cookie = cookie_gen(uname);
            strcpy((msg->clinfo).nounce, cookie);
            free(cookie);

            fclose(shadow_fptr);
            return true;
        }
    }

    fclose(shadow_fptr);
    return false;
}

static _Bool http_post_handler(int connfd, HTTPMsg *msg){
    // get payload length
    char *content_len_ptr;
    if((content_len_ptr = strstr(msg->buf.val, "Content-Length: ")))
        content_len_ptr += 16;
    else {
        http_err_send(connfd, 411, 0);
        return false;
    }

    size_t content_len = (size_t) strtol(content_len_ptr, NULL, 10);
    if(content_len > MAX_CONTENT_LENGTH){
        http_err_send(connfd, 413, 0);
        return false;
    } 

    _Bool is_authorized = false;
    _Bool success;
    Sb res_hdr_buf;

    if(strstr(msg->buf.val, "login")){ // login
        success = login(msg);
        if(success){
            // fixme: cookie
            http_redirect_send(connfd, 303, "/main.html", 1, "Set-Cookie: auth=abc123");
            printf("after login: %p, strlen: %zu\n", msg, strlen(msg->clinfo.name));
        } else { 
            http_redirect_send(connfd, 303, "/login_failed.html", 0);
        }
    } else if(strstr(msg->buf.val, "register")){ // register
        success = signup(msg);
        if(success) {
            http_redirect_send(connfd, 303, "/register_success.html", 0);
        } else { 
            http_redirect_send(connfd, 303, "/register_failed.html", 0);
        }
    } else if(strstr(msg->buf.val, "upload")){ // upload
        printf("upload: %p, strlen: %zu\n", msg, strlen(msg->clinfo.name));

        // char *line_feed_ptr;
        // char *filename_ptr = strstr(msg->buf.val, "filename");
        // // get content type to separate binary or ascii
        // char content_type[32];
        // char *content_type_ptr;
        // content_type_ptr = strstr(filename_ptr, "Content-Type: ") + 14;
        // line_feed_ptr = strstr(content_type_ptr, CRLF);
        // memcpy(content_type, content_type_ptr, line_feed_ptr - content_type_ptr);
        // printf("%s\n", content_type);

        // get message body
        size_t recv_size_tot = 0;
        size_t recv_size;
        char buf[BUF_SIZE];
            while(recv_size_tot < content_len){
            iagain:
                recv_size = recv(connfd, buf, BUF_SIZE, 0);
                if(recv_size == -1)
                    err_handle("recv message body", iagain);
                sb_puts(&msg->buf, buf);
                recv_size_tot += recv_size;
            }
            printf("recv_size: %zu\n", recv_size_tot);
        // fixme if need rb
        // if(strncmp(content_type, "image", 5) == 0){
        //     printf("img here\n");
        // } else if(strncmp(content_type, "text", 4) == 0){
        //     printf("text here\n");
        //     while(recv_size_tot < content_len){
        //     tagain:
        //         recv_size = recv(connfd, buf, BUF_SIZE, 0);
        //         if(recv_size == -1)
        //             err_handle("recv message body", tagain);
        //         sb_puts(&msg->buf, buf);
        //         recv_size_tot += recv_size;
        //     }
        //     printf("recv_size: %zu\n", recv_size_tot);
        // } else { // unsupported content type
        //     http_err_send(connfd, 406, 0);   
        // }

        char *cookie = get_cookie(msg);
        if(cookie && strcmp(cookie, msg->clinfo.nounce) == 0)
            is_authorized = true;

        if(is_authorized){
            success = file_upload(msg);
            http_redirect_send(connfd, 303, "/upload_success.html", 0);
        } else {
            http_err_send(connfd, 401, 0);
        }

        free(cookie);
    }    
    printf("redirect fin: %p, strlen: %zu\n", msg, strlen(msg->clinfo.name));
    return success;
}

static _Bool file_upload(HTTPMsg *msg){
    char *hdr = sb_flush(&msg->buf);

    // get content length
    size_t content_len;
    content_len = strtol(strstr(hdr, "Content-Length") + 16, NULL, 10);
    
    char *line_feed_ptr;
    char *next_line_feed_ptr;

    // get end boundary (boundary + "--")
    char boundary_end[BUF_SIZE];
    memset(boundary_end, 0, sizeof(char[BUF_SIZE]));
    memcpy(boundary_end, "--", 2);
    size_t boundary_len;
    char *boundary_ptr = strstr(hdr, "boundary=") + 9;
    line_feed_ptr = strchr(boundary_ptr, '\r');
    boundary_len = line_feed_ptr - boundary_ptr;
    strncat(boundary_end, boundary_ptr, boundary_len);
    strcat(boundary_end, "--");
    size_t boundary_end_len = boundary_len + 4;

    // get filename;
    char filename[PATH_MAX] = {0};
    char *filename_ptr = strstr(hdr, "filename") + 10;
    char *quote_end_ptr = strchr(filename_ptr, '"');
    memcpy(filename, filename_ptr, quote_end_ptr - filename_ptr);

    // get content type to separate binary or ascii
    char content_type[32];
    char *content_type_ptr;
    content_type_ptr = strstr(filename_ptr, "Content-Type: ") + 14;
    line_feed_ptr = strstr(content_type_ptr, CRLF);
    memcpy(content_type, content_type_ptr, line_feed_ptr - content_type_ptr);

    // get content start
    char *content_start_ptr = strstr(filename_ptr, CRLF CRLF) + 4;

    // create file
    char file_dest[PATH_MAX] = "./users/";
    char *username = msg->clinfo.name;
    // fixme
    // strcat(file_dest, username);
    strcat(file_dest, "test/");
    strcat(file_dest, filename);
    int newfd = open(file_dest, O_CREAT | O_RDWR | S_IRWXU | S_IRWXG);

    // printf("file_dest: %s\n", file_dest);
    // printf("filename: %s\n", filename);
    // printf("bound_end: %s\n", boundary_end);
    // printf("%s", hdr);
    // printf("%s", content_start_ptr);

    // write octets to newly created file
    ssize_t write_size;
    size_t to_write;
    char tmpbuf[4096];

    if(strncmp(content_type, "image", 5) == 0){
        printf("content type: %s\n", content_type);
        FILE *bin_fptr;
    again:
        bin_fptr = fdopen(newfd, "wb");
        if(!bin_fptr)
            err_handle("fdopen write binary", again);

        while(1){
            line_feed_ptr = strstr(content_start_ptr, CRLF);
            next_line_feed_ptr = strstr(line_feed_ptr, CRLF);
            to_write = line_feed_ptr - content_start_ptr + 2; // +2 for CRLF

            if(strncmp(next_line_feed_ptr + 2, boundary_end, boundary_end_len) == 0){
                to_write -= 2; //skip last line
                fwrite(content_start_ptr, sizeof *content_start_ptr, to_write, bin_fptr);
                printf("CRLF double\n");
                break;
            }
            
            fwrite(content_start_ptr, sizeof *content_start_ptr, to_write, bin_fptr);
            snprintf(tmpbuf, to_write, "%s", line_feed_ptr);
            size_t count = to_write;
            char *ptr = tmpbuf;
            while(count > 0){
                for(int i = 0; i < 16; ++i){
                    printf("%x ", (unsigned int) (*(ptr + i)));
                }
                printf("\n");
                ptr += 16;
                count -= 16;
            }

            content_start_ptr = line_feed_ptr + 2;
            memset(tmpbuf, 0, sizeof(char[4096]));
        }

    } else if(strncmp(content_type, "text", 4) == 0){
        while(1){
            line_feed_ptr = strstr(content_start_ptr, CRLF);
            next_line_feed_ptr = strstr(line_feed_ptr, CRLF);
            to_write = line_feed_ptr - content_start_ptr + 2; // +2 for CRLF

            if(strncmp(next_line_feed_ptr + 2, boundary_end, boundary_end_len) == 0){
                to_write -= 2; //skip last line
                write(newfd, content_start_ptr, to_write);
                break;
            }
            
            write(newfd, content_start_ptr, to_write);
            // snprintf(tmpbuf, to_write, "%s", line_feed_ptr);
            // printf("%s\n", tmpbuf);

            content_start_ptr = line_feed_ptr + 2;
            // memset(tmpbuf, 0, sizeof(char[4096]));
        }
    } 

    close(newfd);
    free(hdr);
    return true;
}

static _Bool http_get_handler(int connfd, HTTPMsg *msg){
    // get request target
    Sb req_tgt_path_buf;
    sb_init(&req_tgt_path_buf, 5);
    sb_putc(&req_tgt_path_buf, '.');
    char *ptr = strstr(msg->buf.val, "/");
    char *qtr = strstr(ptr, " "); 
    sb_putn(&req_tgt_path_buf, ptr, qtr - ptr);
    if(req_tgt_path_buf.size == 2) 
        sb_puts(&req_tgt_path_buf, "index.html");

    // get content type
    char *req_tgt_path = sb_flush(&req_tgt_path_buf);
    char *content_type = get_content_type(req_tgt_path);
    if(!content_type){
        http_err_send(connfd, 415, 0);
        return false;
    }

    int req_tgt_fd = open(req_tgt_path, O_RDONLY);
    // 404 not found except view.html and download
    if(req_tgt_fd == -1 && !strstr(req_tgt_path, "view") && !strstr(req_tgt_path, "download")){
        http_err_send(connfd, 404, 0);
        return false;
    } 
    
    // page protection
    if(strstr(content_type, "html") || strstr(content_type, "plain")){
        char *cookie = get_cookie(msg);
        if(cookie) {
            if(strstr(req_tgt_path, "download")){
                char download_tgt[PATH_MAX];
                memset(download_tgt, 0, sizeof(char[PATH_MAX]));
                char *download_tgt_ptr = strstr(msg->buf.val, "/download/") + 10;
                char *space = strchr(download_tgt_ptr, ' ');
                memcpy(download_tgt, download_tgt_ptr, space - download_tgt_ptr);

                if(access(download_tgt, F_OK) == ENOENT)
                    http_err_send(connfd, 400, 0);
                else {
                    char content_dispo_hdr[PATH_MAX];
                    strcpy(content_dispo_hdr, "Content-Disposition: attachment; filename=");
                    strcat(content_dispo_hdr, basename(download_tgt));
                    http_resrc_send(connfd, 200, download_tgt, 1, content_dispo_hdr);
                }
            } else if(strstr(req_tgt_path, "main") || strstr(req_tgt_path, "index")){
                http_resrc_send(connfd, 200, "./main.html", 0);
            } else if(strstr(req_tgt_path, "view")){
                int view_fd = open("./view.html", O_CREAT | O_TRUNC | O_RDWR, S_IRWXU | S_IRWXG);
                char buf[BUF_SIZE];
                ssize_t read_size;

                // view header
                int view_hdr_fd = open("./view_header.html", O_RDONLY);
                while((read_size = read(view_hdr_fd, buf, BUF_SIZE)) > 0)
                    write(view_fd, buf, read_size);
                close(view_hdr_fd);

                // view body
                char user_dir_path[32];
                strcpy(user_dir_path, "./users/");
                strcat(user_dir_path, "test");
                // fixme
                // strcat(user_dir_path, msg->clinfo.name);

                DIR *dir_user = opendir(user_dir_path);
                struct dirent *e;
                char *li_tag_start = "<li><a href=\"http://localhost/download/";
                char *li_tag_end = "</a></li>";
                size_t li_tag_start_len = strlen(li_tag_start);
                size_t li_tag_end_len = strlen(li_tag_end);

                while((e = readdir(dir_user))){
                    if(strncmp(e->d_name, ".", 1) == 0 || strncmp(e->d_name, "..", 2) == 0)
                        continue;
                    write(view_fd, li_tag_start, li_tag_start_len);
                    write(view_fd, "users/", 6);
                    // fixme:
                    write(view_fd, "test/", 5);
                    write(view_fd, e->d_name, strlen(e->d_name));
                    write(view_fd, "\">", 2);
                    write(view_fd, e->d_name, strlen(e->d_name));
                    write(view_fd, li_tag_end, li_tag_end_len);
                }

                // view footer
                int view_ftr_fd = open("./view_footer.html", O_RDONLY);
                while((read_size = read(view_ftr_fd, buf, BUF_SIZE)) > 0)
                    write(view_fd, buf, read_size);
                close(view_ftr_fd);

                closedir(dir_user);
                close(view_fd);

                http_resrc_send(connfd, 200, "view.html", 0);
            } else { 
                http_resrc_send(connfd, 200, req_tgt_path, 0);
            }
        } else if(!cookie || (strcmp(cookie, msg->clinfo.nounce) != 0)){
            if(strstr(req_tgt_path, "main") || 
                strstr(req_tgt_path, "view") || strstr(req_tgt_path, "index"))
                http_resrc_send(connfd, 200, "./index.html", 0);
            else {
                http_resrc_send(connfd, 200, req_tgt_path, 0);
            }
        }
    } else {
        http_resrc_send(connfd, 200, req_tgt_path, 0);
    }

    free(content_type);
    free(req_tgt_path);
    close(req_tgt_fd);
    return true;
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

static void sb_clear(Sb *buf){
    *(buf->val) = '\0';
    buf->size = 0;
    return;
}

static char *get_content_type(char *req_tgt){
    Sb buf;
    sb_init(&buf, 5);
    if(strstr(req_tgt, ".jpg") || strstr(req_tgt, ".png") || strstr(req_tgt, ".jpeg"))
        sb_puts(&buf, "Content-Type: image/jpeg");
    else if(strstr(req_tgt, ".gif"))
        sb_puts(&buf, "Content-Type: image/gif");
    else if(strstr(req_tgt, "html"))
        sb_puts(&buf, "Content-Type: text/html; charset=utf-8");
    else if(strstr(req_tgt, "txt"))
        sb_puts(&buf, "Content-Type: text/plain; charset=utf-8");
    else if(strstr(req_tgt, "upload"))
        sb_puts(&buf, "upload");
    else { // unsupport type
        free(sb_flush(&buf));
        return NULL;
    }

    return sb_flush(&buf);
}

static char *code2msg(int code){
    Sb ret;
    sb_init(&ret, 5);
    switch(code){
        case 200:
            sb_puts(&ret, "OK");
            break;
        // case 201:
        //     sb_puts(&ret, "Created");
        //     break;
        case 303:
            sb_puts(&ret, "See Other");
            break;
        case 400:
            sb_puts(&ret, "Bad Request");
            break;
        case 401:
            sb_puts(&ret, "Unauthorized");
            break;
        case 404:
            sb_puts(&ret, "Not Found");
            break;
        case 405:
            sb_puts(&ret, "Method Not Allowed");
            break;
        case 406:
            sb_puts(&ret, "Not Acceptable");
            break;
        case 411:
            sb_puts(&ret, "Length Required");
            break;
        case 413:
            sb_puts(&ret, "Payload Too Large");
            break;
        case 415:
            sb_puts(&ret, "Unsupported Media Type");
            break;
        default:
            break;
    }

    return sb_flush(&ret);
}

static void http_err_send(int connfd, int code, int hdr_cnt, ...){

    char *msg = code2msg(code);
    char code_buf[4];
    sprintf(code_buf, "%d", code);

    Sb err_res_hdr_buf;
    sb_init(&err_res_hdr_buf, 5);

    sb_puts(&err_res_hdr_buf, "HTTP/1.1 ");
    sb_puts(&err_res_hdr_buf, code_buf);
    sb_putc(&err_res_hdr_buf, ' ');
    sb_puts(&err_res_hdr_buf, msg);
    sb_puts(&err_res_hdr_buf, CRLF);

    // additional header if any
    if(hdr_cnt > 0){
        va_list args;
        va_start(args, hdr_cnt);
        for(int i = 0; i <hdr_cnt; ++i){
            sb_puts(&err_res_hdr_buf, va_arg(args, char *));
            sb_puts(&err_res_hdr_buf, CRLF);
        }
        va_end(args);
    }

    sb_puts(&err_res_hdr_buf, "Connection: close");
    sb_puts(&err_res_hdr_buf, CRLF);
    sb_puts(&err_res_hdr_buf, CRLF);

    char *err_res_hdr = sb_flush(&err_res_hdr_buf);
again:
    if(send(connfd, err_res_hdr, err_res_hdr_buf.size, 0) == -1)
        err_handle("err send", again);

    free(msg);
    free(err_res_hdr);
    return;
}

static void http_resrc_send(int connfd, int code, char *req_tgt_path, int hdr_cnt, ...){
    char buf[BUF_SIZE];
    memset(buf, 0, sizeof(char[BUF_SIZE]));
    ssize_t send_size;

    char *code_msg = code2msg(code);
    char code_buf[4];
    sprintf(code_buf, "%d", code);

    char time_buf[100];
    strftime(time_buf, 100, "%a %b %d %T %Y", localtime(&(time_t){time(NULL)}));

    Sb res_hdr_buf;
    sb_init(&res_hdr_buf, 5);

    sb_puts(&res_hdr_buf, "HTTP/1.1 ");
    sb_puts(&res_hdr_buf, code_buf);
    sb_putc(&res_hdr_buf, ' ');
    sb_puts(&res_hdr_buf, code_msg);
    sb_puts(&res_hdr_buf, CRLF);

    // additional header if any
    if(hdr_cnt > 0){
        va_list args;
        va_start(args, hdr_cnt);
        for(int i = 0; i <hdr_cnt; ++i){
            sb_puts(&res_hdr_buf, va_arg(args, char *));
            sb_puts(&res_hdr_buf, CRLF);
        }
        va_end(args);
    }

    sb_puts(&res_hdr_buf, "Date: ");
    sb_puts(&res_hdr_buf, time_buf);
    sb_puts(&res_hdr_buf, CRLF);

    sb_puts(&res_hdr_buf, "Server: cool server");
    sb_puts(&res_hdr_buf, CRLF);

    char *ctt = get_content_type(req_tgt_path);
    sb_puts(&res_hdr_buf, ctt);
    sb_puts(&res_hdr_buf, CRLF);
    free(ctt);

    struct stat req_tgt_stat;
    int req_tgt_fd = open(req_tgt_path, O_RDONLY);
    fstat(req_tgt_fd, &req_tgt_stat);
    sprintf(buf, "%ld", req_tgt_stat.st_size);
    sb_puts(&res_hdr_buf, "Content-Length: ");
    sb_puts(&res_hdr_buf, buf);
    sb_puts(&res_hdr_buf, CRLF);
    sb_puts(&res_hdr_buf, CRLF);

    // send header
    char *res_hdr = sb_flush(&res_hdr_buf);
again:
    if(send(connfd, res_hdr, res_hdr_buf.size - 1, 0) == -1)
        err_handle("err send", again);

    // send payload
    ssize_t read_size;
    while((read_size = read(req_tgt_fd, buf, BUF_SIZE)) > 0){
    sendreqtgtagain:
        send_size = send(connfd, buf, read_size, 0);
        if(send_size != read_size)
            err_handle("send response payload(found)", sendreqtgtagain);
    }

    free(code_msg);
    free(res_hdr);
    close(req_tgt_fd);
    return;
}

static void http_redirect_send(int connfd, int code, char *redirection, int hdr_cnt, ...){
    char *msg = code2msg(code);
    char code_buf[4];
    sprintf(code_buf, "%d", code);

    Sb redirect_res_hdr_buf;
    sb_init(&redirect_res_hdr_buf, 5);

    sb_puts(&redirect_res_hdr_buf, "HTTP/1.1 ");
    sb_puts(&redirect_res_hdr_buf, code_buf);
    sb_putc(&redirect_res_hdr_buf, ' ');
    sb_puts(&redirect_res_hdr_buf, msg);
    sb_puts(&redirect_res_hdr_buf, CRLF);

    // additional header if any
    if(hdr_cnt > 0){
        va_list args;
        va_start(args, hdr_cnt);
        for(int i = 0; i < hdr_cnt; ++i){
            sb_puts(&redirect_res_hdr_buf, va_arg(args, char *));
            sb_puts(&redirect_res_hdr_buf, CRLF);
        }
        va_end(args);
    }

    sb_puts(&redirect_res_hdr_buf, "Location: ");
    sb_puts(&redirect_res_hdr_buf, redirection);
    sb_puts(&redirect_res_hdr_buf, CRLF);
    sb_puts(&redirect_res_hdr_buf, CRLF);

    char *redirect_res_hdr = sb_flush(&redirect_res_hdr_buf);
again:
    if(send(connfd, redirect_res_hdr, redirect_res_hdr_buf.size, 0) == -1)
        err_handle("err send", again);

    free(msg);
    free(redirect_res_hdr);
    return;
}

static char *get_cookie(HTTPMsg *msg){
    char *cookie_ptr = strstr(msg->buf.val, "Cookie: ");
    if(!cookie_ptr)
        return NULL;

    char *auth_ptr = strstr(cookie_ptr, "auth=");
    if(!auth_ptr)
        return NULL;
    auth_ptr += 5;

    char *linefeed_ptr = strstr(auth_ptr, CRLF);

    char *auth_cookie = malloc(64);
    memcpy(auth_cookie, auth_cookie, linefeed_ptr - auth_ptr);

    return auth_cookie;
}

// simply +1 to each character of username
static char *cookie_gen(char *username){
    char *cookie = malloc(strlen(username) + 1);
    strcpy(cookie, username);
    for(size_t i = 0; i < strlen(cookie); ++i)
        *(cookie + i) += 1;
    return cookie;
}

static void get_uname_psw(HTTPMsg *msg, char *uname, char *psw){
    char *uname_ptr;
    char *psw_ptr;
    char *ptr, *qtr;
    size_t content_len;
    content_len = strtol(strstr(msg->buf.val, "Content-Length") + 16, NULL, 10);

    // printf("%s\n", msg->buf.val);

    uname_ptr = strstr(msg->buf.val, CRLF CRLF) + 10;
    ptr = strchr(uname_ptr, '&');
    psw_ptr = ptr + 1;
    
    memcpy(uname, uname_ptr, ptr - uname_ptr);
    content_len -= (6 + (ptr - uname_ptr) + 4);   // password length
    memcpy(psw, psw_ptr + 4, content_len);
}

static void clinfo_init(ClientInfo *clinfo){
    clinfo->name = malloc(64);
    memset(clinfo->name, 0, 64);

    clinfo->nounce = malloc(16);
    memset(clinfo->name, 0, 16);
    return;
}

static void clinfo_destroy(ClientInfo *clinfo){
    free(clinfo->name);
    free(clinfo->nounce);
}