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
#define MAX_CONTENT_LENGTH 0x100000  // 1MB
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

typedef struct http_msg {
    Sb buf;
} HTTPMsg;

static _Bool http_get_handler(int connfd, HTTPMsg *msg);
static _Bool http_post_handler(int connfd, HTTPMsg *msg);
static void http_err_send(int connfd, int code, int hdr_cnt, ...);
static void http_resrc_send(int connfd, int code, char *req_tgt_path, int hdr_cnt, ...);
static void http_redirect_send(int connfd, int code, char *redirection, int hdr_cnt, ...);

static int signup(HTTPMsg *msg);
static _Bool login(HTTPMsg *msg);
static _Bool file_upload(HTTPMsg *msg);
static void get_uname_psw_from_msg(HTTPMsg *msg, char *uname, char *psw);
static char *get_content_type(char *req_tgt);
static char *code2msg(int code);
static char *get_cookie(HTTPMsg *msg);
static char *get_uname_from_cookie(char *cookie);
static _Bool check_nounce(char *cookie);
static void save_uname_nounce(char *uname, char *nounce);
static char *nounce_gen(char *username);
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
    char buf[BUF_SIZE] = {0};

    HTTPMsg msg;
    sb_init(&msg.buf, 5);

    char *ptr, *qtr;
    _Bool is_get = false;     // only support get and post method
    _Bool success;

    while(1){
    next:
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
                printf("failed post!\n");
                goto end;
            }
        }
    }
end:
    printf("end!\n");
    free(sb_flush(&msg.buf));
    close(connfd);
    return;
}

static int signup(HTTPMsg *msg){
    char uname[11] = {0};
    char psw[9] = {0};
    get_uname_psw_from_msg(msg, uname, psw);

    // check if any same username exists
    DIR *dir_user = opendir("./users/");
    struct dirent *entry_user;

    while((entry_user = readdir(dir_user))){
        if(strcmp(entry_user->d_name, uname) == 0)
            return 1;
    }

    int direcfd = dirfd(dir_user);
    if(direcfd == -1)
        return 2;
    if(mkdirat(direcfd, uname, S_IRUSR | S_IWUSR | S_IRGRP | S_IWGRP | S_IRWXO) == -1)
        return 2;

    int shadowfd = open("./shadow", O_APPEND | O_WRONLY);
    char rec_new[32] = {0};
    strcpy(rec_new, uname);
    strcat(rec_new, ":");
    strcat(rec_new, psw);
    strcat(rec_new, "\n");
    write(shadowfd, rec_new, strlen(rec_new));

    close(shadowfd);
    close(direcfd);
    return 0;
}

static _Bool login(HTTPMsg *msg){
    char uname[11] = {0};
    char psw[9] = {0};
    get_uname_psw_from_msg(msg, uname, psw);

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

    if(strstr(msg->buf.val, "login")){ // login
        success = login(msg);

        if(success){
            char uname[11] = {0};
            char psw[9] = {0};
            get_uname_psw_from_msg(msg, uname, psw);

            char cookie1[64] = {0}; // nounce
            strcpy(cookie1, "Set-Cookie: ");
            char *nounce = nounce_gen(uname);
            strcat(cookie1, "auth=");
            strcat(cookie1, nounce);

            char cookie2[64] = {0}; // uname
            strcpy(cookie2, "Set-Cookie: ");
            strcat(cookie2, "uname=");
            strcat(cookie2, uname);

            save_uname_nounce(uname, nounce);
            free(nounce);

            http_redirect_send(connfd, 303, "/main.html", 2, cookie1, cookie2);
        } else 
            http_redirect_send(connfd, 303, "/login_failed.html", 0);
    } else if(strstr(msg->buf.val, "register")){ // register
        int ret;
        ret = signup(msg);
        if(ret == 1)
            http_redirect_send(connfd, 303, "/register_failed.html", 0);
        else if(ret == 2)
            http_err_send(connfd, 500, 0);
        else {   // success
            success = true;
            http_redirect_send(connfd, 303, "/register_success.html", 0);
        } 
    } else if(strstr(msg->buf.val, "upload")){ // upload
        // get message body
        size_t recv_size_tot = 0;
        size_t recv_size;
        char buf[BUF_SIZE] = {0};
        while(recv_size_tot < content_len){
            recv_size = recv(connfd, buf, BUF_SIZE, 0);
            sb_puts(&msg->buf, buf);
            recv_size_tot += recv_size;
        }
        printf("recv_size: %zu\n", recv_size_tot);

        is_authorized = check_nounce(get_cookie(msg));
        if(is_authorized){
            success = file_upload(msg);
            if(success)
                http_redirect_send(connfd, 303, "/upload_success.html", 0);
            else
                http_err_send(connfd, 500, 0);
        } else
            http_err_send(connfd, 401, 0);
    }    
    return success;
}

static _Bool file_upload(HTTPMsg *msg){
    char *uname = get_uname_from_cookie(get_cookie(msg));
    char *hdr = sb_flush(&msg->buf);
    
    // get content length
    size_t content_len;
    content_len = strtol(strstr(hdr, "Content-Length") + 16, NULL, 10);
    
    char *line_feed_ptr;
    char *next_line_feed_ptr;

    // get end boundary (boundary + "--")
    char boundary_end[BUF_SIZE] = {0};
    memcpy(boundary_end, "--", 2);
    size_t boundary_len;
    char *boundary_ptr = strstr(hdr, "boundary=") + 9;
    line_feed_ptr = strchr(boundary_ptr, '\r');
    boundary_len = line_feed_ptr - boundary_ptr;
    strncat(boundary_end, boundary_ptr, boundary_len);
    strcat(boundary_end, "--");
    size_t boundary_end_len = boundary_len + 4;

    // get content disposition
    char content_dispo[BUF_SIZE] = {0};
    char *content_dispo_ptr = strstr(hdr, "Content-Disposition");
    line_feed_ptr = strstr(content_dispo_ptr, CRLF);
    memcpy(content_dispo, content_dispo_ptr, line_feed_ptr - content_dispo_ptr);

    // get filename;
    char filename[PATH_MAX] = {0};
    char *filename_ptr = strstr(content_dispo_ptr, "filename") + 10;
    char *quote_end_ptr = strchr(filename_ptr, '"');
    memcpy(filename, filename_ptr, quote_end_ptr - filename_ptr);

    // get content type to separate binary or ascii
    char content_type[PATH_MAX] = {0};
    char *content_type_ptr;
    content_type_ptr = strstr(filename_ptr, "Content-Type: ") + 14;
    line_feed_ptr = strstr(content_type_ptr, CRLF);
    memcpy(content_type, content_type_ptr, line_feed_ptr - content_type_ptr);

    // get content start
    char *content_start_ptr = strstr(filename_ptr, CRLF CRLF) + 4;
    // char tmpbuf[1024];
    // snprintf(tmpbuf, 128, "%s", content_start_ptr);
    // for(int i = 0; i < 128; ++i){
    //     for(int j = i; j < i + 16; ++j)
    //         printf("%X ", tmpbuf[j]);
    //     printf("\n");
    // }

    // create file
    char file_dest[PATH_MAX] = "./users/";
    strcat(file_dest, uname);
    strcat(file_dest, "/");
    strcat(file_dest, filename);
    free(uname);

    // write octets to newly created file
    if(strncmp(content_type, "image", 5) == 0 || 
        strncmp(content_type, "application/vnd.openxmlformats-officedocument.wordprocessingml.document", strlen("application/vnd.openxmlformats-officedocument.wordprocessingml.document")) == 0){
        FILE *dest_fptr = fopen(file_dest, "wb");
        if(!dest_fptr){
            free(hdr);
            return false;
        }
        size_t real_content_len = content_len - boundary_end_len - (boundary_end_len + 2) - strlen(content_type) - strlen(content_dispo) - 22; // 22 is CRLF
        fwrite(content_start_ptr, 1, real_content_len, dest_fptr);
        fclose(dest_fptr);
    } else if(strncmp(content_type, "text", 4) == 0){
        int newfd = open(file_dest, O_CREAT | O_TRUNC | O_RDWR, S_IRWXU | S_IRWXG);
        if(newfd == -1){
            free(hdr);
            return false;
        }

        ssize_t write_size;
        size_t to_write;
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
            content_start_ptr = line_feed_ptr + 2;
        }
        close(newfd);
    } 

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
        free(req_tgt_path);
        return false;
    }

    if(strstr(req_tgt_path, "view") || strstr(req_tgt_path, "logout") || strstr(req_tgt_path, "download"))
        goto serve;

    // 404 not found
    int req_tgt_fd = open(req_tgt_path, O_RDONLY);
    if(req_tgt_fd == -1){
        http_err_send(connfd, 404, 0);
        free(req_tgt_path);
        return false;
    } 

    char *cookie;
    // page protection
serve:
    cookie = get_cookie(msg);
    if(cookie && check_nounce(cookie)) {
        if(strstr(req_tgt_path, "logout")){
            // set expire of cookie and redirect
            char *uname = get_uname_from_cookie(get_cookie(msg));
            char cookie1[64] = {0}; // nounce
            strcpy(cookie1, "Set-Cookie: ");
            char *nounce = nounce_gen(uname);
            strcat(cookie1, "auth=");
            strcat(cookie1, nounce);
            strcat(cookie1, "; expires=Thu, 01 Jan 1970 00:00:00 GMT");
            free(nounce);

            char cookie2[64] = {0}; // uname
            strcpy(cookie2, "Set-Cookie: ");
            strcat(cookie2, "uname=");
            strcat(cookie2, uname);
            strcat(cookie2, "; expires=Thu, 01 Jan 1970 00:00:00 GMT");

            http_redirect_send(connfd, 303, "/index.html", 2, cookie1, cookie2);
        } else if(strstr(req_tgt_path, "download")){
            char download_tgt[PATH_MAX] = {0};
            char *download_tgt_ptr = strstr(msg->buf.val, "/download/") + 10;
            char *space = strchr(download_tgt_ptr, ' ');
            memcpy(download_tgt, download_tgt_ptr, space - download_tgt_ptr);

            if(access(download_tgt, F_OK) == ENOENT)
                http_err_send(connfd, 400, 0);
            else {
                char content_dispo_hdr[PATH_MAX] = {0};
                strcpy(content_dispo_hdr, "Content-Disposition: attachment; filename=");
                strcat(content_dispo_hdr, basename(download_tgt));
                http_resrc_send(connfd, 200, download_tgt, 1, content_dispo_hdr);
                goto end;
            }
        }  else if(strstr(req_tgt_path, "view")){
            char *cookie = get_cookie(msg);
            char *uname = get_uname_from_cookie(cookie);

            char user_dir_path[32];
            strcpy(user_dir_path, "./users/");
            strcat(user_dir_path, uname);
            strcat(user_dir_path, "/");

            char user_view_path[32];
            strcpy(user_view_path, user_dir_path);
            strcat(user_view_path, "/");
            strcat(user_view_path, "view.html");

            int view_fd = open(user_view_path, O_CREAT | O_TRUNC | O_RDWR, S_IRWXU | S_IRWXG);
            if(view_fd == -1){
                http_err_send(connfd, 500, 0);
                free(uname);
                return false;
            }

            char buf[BUF_SIZE] = {0};
            ssize_t read_size;

            // view header
            int view_hdr_fd = open("./view_header.html", O_RDONLY);
            while((read_size = read(view_hdr_fd, buf, BUF_SIZE)) > 0)
                write(view_fd, buf, read_size);
            close(view_hdr_fd);

            // view body
            DIR *dir_user = opendir(user_dir_path);
            struct dirent *e;
            char *li_tag_start = "<li><a href=\"http://localhost/download/";
            char *li_tag_end = "</a></li>";
            size_t li_tag_start_len = strlen(li_tag_start);
            size_t li_tag_end_len = strlen(li_tag_end);

            while((e = readdir(dir_user))){
                if(strncmp(e->d_name, ".", 1) == 0 || 
                    strncmp(e->d_name, "..", 2) == 0 ||
                    strncmp(e->d_name, "view.html", 9) == 0)
                    continue;
                write(view_fd, li_tag_start, li_tag_start_len);
                write(view_fd, "users/", 6);
                write(view_fd, uname, strlen(uname));
                write(view_fd, "/", 1);
                write(view_fd, e->d_name, strlen(e->d_name));
                write(view_fd, "\">", 2);
                write(view_fd, e->d_name, strlen(e->d_name));
                write(view_fd, li_tag_end, li_tag_end_len);
            }
            free(uname);

            // view footer
            int view_ftr_fd = open("./view_footer.html", O_RDONLY);
            while((read_size = read(view_ftr_fd, buf, BUF_SIZE)) > 0)
                write(view_fd, buf, read_size);

            closedir(dir_user);
            close(view_fd);
            close(view_ftr_fd);

            http_resrc_send(connfd, 200, user_view_path, 0);
        } else if(strstr(req_tgt_path, "main") || strstr(req_tgt_path, "index"))
            http_resrc_send(connfd, 200, "./main.html", 0);
        else
            http_resrc_send(connfd, 200, req_tgt_path, 0);
    } else {
        if(strstr(req_tgt_path, "main") || 
            strstr(req_tgt_path, "view") || strstr(req_tgt_path, "index"))
            http_resrc_send(connfd, 200, "./index.html", 0);
        else
            http_resrc_send(connfd, 200, req_tgt_path, 0);
    }

    close(req_tgt_fd);
end:
    free(content_type);
    free(req_tgt_path);
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

//   ret = strdup(realloc(buf->val, size)); /* using strdup since realloc may remain the same region of memory */
//   free(buf->val);
  return buf->val;
}

static void sb_clear(Sb *buf){
    *(buf->val) = '\0';
    buf->size = 0;
    return;
}

static char *get_content_type(char *req_tgt){
    Sb buf;
    sb_init(&buf, 5);
    if(strstr(req_tgt, ".jpg") || strstr(req_tgt, ".png") || strstr(req_tgt, ".jpeg") || strstr(req_tgt, ".ico"))
        sb_puts(&buf, "Content-Type: image/jpeg");
    else if(strstr(req_tgt, ".gif"))
        sb_puts(&buf, "Content-Type: image/gif");
    else if(strstr(req_tgt, ".docx"))
        sb_puts(&buf, "Content-Type: application/vnd.openxmlformats-officedocument.wordprocessingml.document");
    else if(strstr(req_tgt, ".html"))
        sb_puts(&buf, "Content-Type: text/html; charset=utf-8");
    else if(strstr(req_tgt, ".txt")) 
        sb_puts(&buf, "Content-Type: text/plain; charset=utf-8");
    else if(strstr(req_tgt, "upload"))
        sb_puts(&buf, "upload");
    else if(strstr(req_tgt, "download"))
        sb_puts(&buf, "download");
    else if(strstr(req_tgt, "logout"))
        sb_puts(&buf, "logout");
    else // unsupport type
        return NULL;

    return sb_flush(&buf);
}

static char *code2msg(int code){
    Sb ret;
    sb_init(&ret, 5);
    switch(code){
        case 200:
            sb_puts(&ret, "OK");
            break;
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
        case 411:
            sb_puts(&ret, "Length Required");
            break;
        case 413:
            sb_puts(&ret, "Payload Too Large");
            break;
        case 415:
            sb_puts(&ret, "Unsupported Media Type");
            break;
        case 500:
            sb_puts(&ret, "Internal Server Error");
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
    send(connfd, err_res_hdr, err_res_hdr_buf.size, 0);

    free(msg);
    free(err_res_hdr);
    return;
}

static void http_resrc_send(int connfd, int code, char *req_tgt_path, int hdr_cnt, ...){
    char buf[BUF_SIZE] = {0};
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
    send(connfd, res_hdr, res_hdr_buf.size - 1, 0);

    // send payload
    ssize_t read_size;
    while((read_size = read(req_tgt_fd, buf, BUF_SIZE)) > 0)
        send(connfd, buf, read_size, 0);

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
    send(connfd, redirect_res_hdr, redirect_res_hdr_buf.size, 0);

    free(msg);
    free(redirect_res_hdr);
    return;
}

static char *get_cookie(HTTPMsg *msg){
    char *cookie_ptr = strstr(msg->buf.val, "Cookie");
    if(!cookie_ptr)
        return NULL;
    return cookie_ptr;
}

static _Bool check_nounce(char *cookie){
    char nounce[64] = {0};
    char uname[64] = {0};

    char *nounce_ptr = strstr(cookie, "auth=");
    nounce_ptr += 5;
    char *semicomma_ptr = strchr(nounce_ptr, ';');
    memcpy(nounce, nounce_ptr, semicomma_ptr - nounce_ptr);

    char *uname_ptr = strstr(cookie, "uname=");
    uname_ptr += 6;
    char *linefeed_ptr = strstr(uname_ptr, CRLF);
    memcpy(uname, uname_ptr, linefeed_ptr - uname_ptr);

    char nounce_rec[128];
    strcpy(nounce_rec, uname);
    strcat(nounce_rec, ":");
    strcat(nounce_rec, nounce);

    FILE *nounce_fptr = fopen("./nounce_shadow", "r");
    if(!nounce_fptr)
        return NULL;

    char buf[BUF_SIZE] = {0};
    size_t buf_len;
    while(fgets(buf, BUF_SIZE, nounce_fptr)){
        buf_len = strlen(buf);
        if(buf_len && buf[buf_len - 1] == '\n')
            buf[buf_len - 1] = 0;

        if(strcmp(nounce_rec, buf) == 0){
            fclose(nounce_fptr);
            return true;
        }
    }

    fclose(nounce_fptr);
    return false;
}

static void save_uname_nounce(char *uname, char *nounce){
    char nounce_rec[128];
    strcpy(nounce_rec, uname);
    strcat(nounce_rec, ":");
    strcat(nounce_rec, nounce);
    strcat(nounce_rec, "\n");

    int nounce_shadowfd = open("./nounce_shadow", O_APPEND | O_WRONLY);
    write(nounce_shadowfd, nounce_rec, strlen(nounce_rec));

    close(nounce_shadowfd);
    return;
}

// simply +1 to each character of username
static char *nounce_gen(char *username){
    char *nounce = malloc(strlen(username) + 1);
    strcpy(nounce, username);
    for(size_t i = 0; i < strlen(nounce); ++i)
        *(nounce + i) += 1;
    return nounce;
}

static void get_uname_psw_from_msg(HTTPMsg *msg, char *uname, char *psw){
    char *uname_ptr;
    char *psw_ptr;
    char *ptr, *qtr;
    size_t content_len;
    content_len = strtol(strstr(msg->buf.val, "Content-Length") + 16, NULL, 10);

    uname_ptr = strstr(msg->buf.val, CRLF CRLF) + 10;
    ptr = strchr(uname_ptr, '&');
    psw_ptr = ptr + 1;
    
    memcpy(uname, uname_ptr, ptr - uname_ptr);
    content_len -= (6 + (ptr - uname_ptr) + 4);   // password length
    memcpy(psw, psw_ptr + 4, content_len);
}

static char *get_uname_from_cookie(char *cookie){
    char *ret = malloc(16);
    if(!ret)
        return NULL;
    memset(ret, 0, 16);

    char *uname_ptr = strstr(cookie, "uname=");
    uname_ptr += 6;
    char *linefeed_ptr = strstr(uname_ptr, CRLF);
    memcpy(ret, uname_ptr, linefeed_ptr - uname_ptr);

    return ret;
}