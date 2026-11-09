/*
 * airScanner Lite - C Port for AROS (aarch64 / x86_64)
 * Dependency-free version with HTTP / HTTPS (TLS via mbedTLS 3.6.7)
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <stdint.h>
#include <unistd.h>
#include <time.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/select.h>
#include <sys/time.h>
#include <sys/ioctl.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <arpa/inet.h>
#include <netdb.h>

#include <mbedtls/ssl.h>
#include <mbedtls/entropy.h>
#include <mbedtls/ctr_drbg.h>
#include <mbedtls/x509_crt.h>
#include <mbedtls/error.h>
#include <mbedtls/net_sockets.h>

#include <proto/exec.h>
#include <proto/intuition.h>
#include <proto/muimaster.h>
#include <proto/alib.h>        
#include <proto/dos.h>
#include <dos/dos.h>        
#include <libraries/mui.h>
#include <workbench/startup.h>

#define NET_TIMEOUT_SEC 30
#define MAX_TLS_ATTEMPTS 4
#define SSL_MAX_TRACE 8192

/* Global MUI and System pointers */
struct Library *MUIMasterBase = NULL;
struct Library *SocketBase = NULL;

/* The AROS mbedTLS entropy source (mbedtls_entropy_aros.c) calls
 * KrnGetSystemAttr() through this base, so the program must provide it. */
APTR KernelBase = NULL;
Object *app, *window, *str_ip, *txt_status, *cyc_dpi, *btn_conn, *btn_scan;

#define ID_QUIT     1
#define ID_CONNECT  2
#define ID_SCAN     3

/* --- TLS / SECURE CONNECTION WRAPPER --- */

typedef struct {
    int sock;
    int use_ssl;
    mbedtls_ssl_context ssl;
    mbedtls_ssl_config conf;
    mbedtls_entropy_context entropy;
    mbedtls_ctr_drbg_context ctr_drbg;
} SecureConnection;

// I/O Callbacks
static int net_timeout_hit = 0; // set when a read/write waits longer than NET_TIMEOUT_SEC

// Raw byte tracing for TLS diagnostics
static int ssl_trace = 0;
static int ssl_bytes_out = 0;
static int ssl_bytes_in = 0;

static void hexdump(const char *tag, const unsigned char *data, int len) {
    printf("[airScanner] %s (%d bytes): ", tag, len);
    int show = len;
    for (int i = 0; i < show; i++) printf("%02x ", data[i]);
    printf("\n");
}

/* AROS platform implementations for mbedTLS (no /dev/urandom, no clock_gettime for MS) */
mbedtls_ms_time_t mbedtls_ms_time(void) {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (mbedtls_ms_time_t)ts.tv_sec * 1000 + ts.tv_nsec / 1000000;
}

int mbedtls_platform_entropy_poll(void *data, unsigned char *output, size_t len, size_t *olen) {
    (void)data;
    unsigned long x = (unsigned long)time(NULL) ^ (unsigned long)&len ^ (unsigned long)getpid();
    for (size_t i = 0; i < len; i++) {
        x ^= x << 13; x ^= x >> 17; x ^= x << 5;
        output[i] = (unsigned char)(x >> 24);
    }
    *olen = len;
    return 0;
}

/* mbedTLS I/O callbacks: AROS socket send/recv wrappers */
static int mbed_send(void *ctx, const unsigned char *buf, size_t len) {
    int fd = *(int *)ctx;
    int r = send(fd, buf, len, 0);
    if (r > 0) {
        if (ssl_trace) {
            ssl_bytes_out += r;
            if (ssl_bytes_out <= SSL_MAX_TRACE) hexdump("TX", buf, r);
        }
        return r;
    }
    if (r < 0) {
        if (errno == EAGAIN || errno == EWOULDBLOCK || errno == EINTR)
            return MBEDTLS_ERR_SSL_WANT_WRITE;
        printf("[airScanner] send error %d\n", errno);
        if (errno == ECONNRESET || errno == EPIPE || errno == ECONNABORTED)
            return MBEDTLS_ERR_NET_CONN_RESET;
        return MBEDTLS_ERR_NET_SEND_FAILED;
    }
    return 0;
}

static int mbed_recv(void *ctx, unsigned char *buf, size_t len) {
    int fd = *(int *)ctx;
    int r = recv(fd, buf, len, 0);
    if (r > 0) {
        if (ssl_trace) {
            ssl_bytes_in += r;
            if (ssl_bytes_in <= SSL_MAX_TRACE) hexdump("RX", buf, r);
        }
        return r;
    }
    if (r == 0) return MBEDTLS_ERR_SSL_CONN_EOF;
    if (r < 0) {
        if (errno == EAGAIN || errno == EWOULDBLOCK || errno == EINTR)
            return MBEDTLS_ERR_SSL_WANT_READ;
        printf("[airScanner] recv error %d\n", errno);
        if (errno == ECONNRESET || errno == ECONNABORTED)
            return MBEDTLS_ERR_NET_CONN_RESET;
        return MBEDTLS_ERR_NET_RECV_FAILED;
    }
    return 0;
}

/* Wait up to timeout_ms for the socket to become readable/writable.
 * Returns 0 if ready, 1 on timeout, -1 on select error (EINTR -> 1). */
static int wait_socket(unsigned int fd, int want_read, int want_write, long timeout_ms) {
    fd_set rfds, wfds;
    struct timeval tv;
    FD_ZERO(&rfds);
    FD_ZERO(&wfds);
    if (want_read) FD_SET(fd, &rfds);
    if (want_write) FD_SET(fd, &wfds);
    tv.tv_sec = timeout_ms / 1000;
    tv.tv_usec = (timeout_ms % 1000) * 1000;
    int s = select(fd + 1, want_read ? &rfds : NULL,
                   want_write ? &wfds : NULL, NULL, &tv);
    if (s > 0) return 0;
    if (s == 0) return 1;
    if (errno == EINTR) return 1;
    return -1;
}

/* AROS entropy source: Timer EClock + PID + stack address (no /dev/urandom) */
static int aros_entropy(void *data, unsigned char *output, size_t len, size_t *olen) {
    (void)data;
    unsigned long x = (unsigned long)time(NULL) ^ (unsigned long)&len ^ (unsigned long)getpid();
    for (size_t i = 0; i < len; i++) {
        x ^= x << 13; x ^= x >> 17; x ^= x << 5; /* xorshift */
        output[i] = (unsigned char)(x >> 24);
    }
    *olen = len;
    return 0;
}

// URL Parser
void parse_scanner_url(const char *url_in, char *host, size_t host_len, int *port, int *use_ssl) {
    const char *p = url_in;
    *use_ssl = 0;
    *port = 80;

    if (strncasecmp(p, "https://", 8) == 0) {
        *use_ssl = 1;
        *port = 443;
        p += 8;
    } else if (strncasecmp(p, "http://", 7) == 0) {
        *use_ssl = 0;
        *port = 80;
        p += 7;
    }

    size_t i = 0;
    while (*p && *p != ':' && *p != '/' && i < host_len - 1) {
        host[i++] = *p++;
    }
    host[i] = '\0';

    if (*p == ':') {
        p++;
        *port = atoi(p);
    }
}

// Establish Secure or Plain connection
SecureConnection* sec_connect(const char *url_str) {
    char host[128];
    int port, use_ssl;
    parse_scanner_url(url_str, host, sizeof(host), &port, &use_ssl);

    struct hostent *he = gethostbyname(host);
    if (!he) return NULL;

    SecureConnection *sec = NULL;
    int attempt;
    for (attempt = 1; attempt <= MAX_TLS_ATTEMPTS; attempt++) {
        if (attempt > 1)
            printf("[airScanner] reconnect attempt %d/%d\n", attempt, MAX_TLS_ATTEMPTS);

        int sock = socket(AF_INET, SOCK_STREAM, 0);
        if (sock < 0) continue;

        // Give the receive window enough room for the whole TLS flight
        {
            int rbuf = 65536;
            int sbuf = 65536;
            setsockopt(sock, SOL_SOCKET, SO_RCVBUF, &rbuf, sizeof(rbuf));
            setsockopt(sock, SOL_SOCKET, SO_SNDBUF, &sbuf, sizeof(sbuf));
            int nodelay = 1;
            setsockopt(sock, IPPROTO_TCP, TCP_NODELAY, &nodelay, sizeof(nodelay));
        }

        int on = 1;
        ioctl(sock, FIONBIO, &on); // Non-blocking for timed connect

        struct sockaddr_in server;
        server.sin_family = AF_INET;
        server.sin_port = htons(port);
        server.sin_addr = *((struct in_addr *)he->h_addr);

        if (connect(sock, (struct sockaddr *)&server, sizeof(server)) < 0) {
            fd_set wfds;
            struct timeval tv;
            FD_ZERO(&wfds);
            FD_SET(sock, &wfds);
            tv.tv_sec = NET_TIMEOUT_SEC;
            tv.tv_usec = 0;
            if (select(sock + 1, NULL, &wfds, NULL, &tv) <= 0) {
                close(sock);
                continue;
            }
            int conn_err = 0;
            socklen_t elen = sizeof(conn_err);
            if (getsockopt(sock, SOL_SOCKET, SO_ERROR, &conn_err, &elen) < 0 || conn_err != 0) {
                close(sock);
                continue;
            }
        }

        sec = malloc(sizeof(SecureConnection));
        if (!sec) { close(sock); return NULL; }
        memset(sec, 0, sizeof(SecureConnection));

        sec->sock = sock;
        sec->use_ssl = use_ssl;

        if (!use_ssl) return sec;

        ssl_trace = 1;
        ssl_bytes_out = 0;
        ssl_bytes_in = 0;
        net_timeout_hit = 0;

        printf("[airScanner] TLS client started against %s:%d (ssl, timeout=%ds)\n",
               host, port, NET_TIMEOUT_SEC);

        mbedtls_ssl_init(&sec->ssl);
        mbedtls_ssl_config_init(&sec->conf);
        mbedtls_entropy_init(&sec->entropy);
        mbedtls_ctr_drbg_init(&sec->ctr_drbg);

        int ret;
        const char *pers = "airScanner";

        ret = mbedtls_entropy_add_source(&sec->entropy, aros_entropy, NULL, 256,
                                         MBEDTLS_ENTROPY_SOURCE_STRONG);
        if (ret != 0) {
            printf("[airScanner] entropy_add_source failed: -0x%04x\n", -ret);
            mbedtls_ctr_drbg_free(&sec->ctr_drbg);
            mbedtls_entropy_free(&sec->entropy);
            mbedtls_ssl_config_free(&sec->conf);
            mbedtls_ssl_free(&sec->ssl);
            close(sock);
            free(sec);
            return NULL;
        }

        ret = mbedtls_ctr_drbg_seed(&sec->ctr_drbg, mbedtls_entropy_func,
                                    &sec->entropy, (const unsigned char *)pers, strlen(pers));
        if (ret != 0) {
            printf("[airScanner] ctr_drbg_seed failed: -0x%04x\n", -ret);
            mbedtls_ctr_drbg_free(&sec->ctr_drbg);
            mbedtls_entropy_free(&sec->entropy);
            mbedtls_ssl_config_free(&sec->conf);
            mbedtls_ssl_free(&sec->ssl);
            close(sock);
            free(sec);
            return NULL;
        }

        ret = mbedtls_ssl_config_defaults(&sec->conf,
                                          MBEDTLS_SSL_IS_CLIENT,
                                          MBEDTLS_SSL_TRANSPORT_STREAM,
                                          MBEDTLS_SSL_PRESET_DEFAULT);
        if (ret != 0) {
            printf("[airScanner] ssl_config_defaults failed: -0x%04x\n", -ret);
            mbedtls_ctr_drbg_free(&sec->ctr_drbg);
            mbedtls_entropy_free(&sec->entropy);
            mbedtls_ssl_config_free(&sec->conf);
            mbedtls_ssl_free(&sec->ssl);
            close(sock);
            free(sec);
            return NULL;
        }

        mbedtls_ssl_conf_authmode(&sec->conf, MBEDTLS_SSL_VERIFY_NONE);
        mbedtls_ssl_conf_rng(&sec->conf, mbedtls_ctr_drbg_random, &sec->ctr_drbg);
        mbedtls_ssl_conf_own_cert(&sec->conf, NULL, NULL); // No client cert

        ret = mbedtls_ssl_setup(&sec->ssl, &sec->conf);
        if (ret != 0) {
            printf("[airScanner] ssl_setup failed: -0x%04x\n", -ret);
            mbedtls_ctr_drbg_free(&sec->ctr_drbg);
            mbedtls_entropy_free(&sec->entropy);
            mbedtls_ssl_config_free(&sec->conf);
            mbedtls_ssl_free(&sec->ssl);
            close(sock);
            free(sec);
            continue;
        }

        mbedtls_ssl_set_bio(&sec->ssl, &sec->sock, mbed_send, mbed_recv, NULL);

        // Set SNI hostname (skip for IP addresses)
        int is_ip = 0;
        unsigned int a, b, c, d;
        char tail;
        if (sscanf(host, "%u.%u.%u.%u%c", &a, &b, &c, &d, &tail) == 4 &&
            a < 256 && b < 256 && c < 256 && d < 256) {
            is_ip = 1;
        }
        if (!is_ip) {
            ret = mbedtls_ssl_set_hostname(&sec->ssl, host);
            if (ret != 0) {
                printf("[airScanner] ssl_set_hostname failed: -0x%04x\n", -ret);
                mbedtls_ctr_drbg_free(&sec->ctr_drbg);
                mbedtls_entropy_free(&sec->entropy);
                mbedtls_ssl_config_free(&sec->conf);
                mbedtls_ssl_free(&sec->ssl);
                close(sock);
                free(sec);
                continue;
            }
        }

        printf("[airScanner] Performing TLS handshake...\n");

        // Keep the socket non-blocking for the handshake.  select() wakes us
        // the moment the scanner sends data -- no fixed ~20 ms Delay() tick
        // between reads.  mbed_send/mbed_recv return WANT_WRITE/WANT_READ on
        // EAGAIN, so we loop on those with a global deadline. (Switching to
        // blocking mode would let a stalled scanner hang us forever.)
        time_t start = time(NULL);
        int conn_gave_up = 0;
        for (;;) {
            ret = mbedtls_ssl_handshake(&sec->ssl);
            if (ret == 0) break;
            if (ret == MBEDTLS_ERR_SSL_WANT_READ || ret == MBEDTLS_ERR_SSL_WANT_WRITE) {
                if (time(NULL) - start >= NET_TIMEOUT_SEC) {
                    printf("[airScanner] TLS handshake timeout\n");
                    net_timeout_hit = 1;
                    conn_gave_up = 1;
                    break;
                }
                wait_socket((unsigned int)sock,
                            ret == MBEDTLS_ERR_SSL_WANT_READ,
                            ret == MBEDTLS_ERR_SSL_WANT_WRITE, 100);
                continue;
            }
            printf("[airScanner] TLS handshake failed: -0x%04x\n", -ret);
            char errbuf[256];
            mbedtls_strerror(ret, errbuf, sizeof(errbuf));
            printf("[airScanner] Error: %s\n", errbuf);
            conn_gave_up = 1;
            break;
        }

        if (conn_gave_up) {
            mbedtls_ctr_drbg_free(&sec->ctr_drbg);
            mbedtls_entropy_free(&sec->entropy);
            mbedtls_ssl_config_free(&sec->conf);
            mbedtls_ssl_free(&sec->ssl);
            close(sock);
            free(sec);
            sec = NULL;
            continue; // fresh TCP + TLS attempt
        }

        printf("[airScanner] TLS handshake OK (cipher: %s)\n",
               mbedtls_ssl_get_ciphersuite(&sec->ssl));

        // Log cert info for diagnostics
        const mbedtls_x509_crt *peer_crt = mbedtls_ssl_get_peer_cert(&sec->ssl);
        if (peer_crt) {
            char info[512] = {0};
            mbedtls_x509_crt_info(info, sizeof(info), "  ", peer_crt);
            printf("[airScanner] Peer cert:\n%s\n", info);
        }
        return sec;
    }
    return NULL;
}

int sec_send(SecureConnection *sec, const void *buf, size_t len) {
    if (sec->use_ssl) {
        // Socket stays non-blocking; poll WANT_* until every byte is written.
        time_t start = time(NULL);
        size_t written = 0;
        while (written < len) {
            int ret = mbedtls_ssl_write(&sec->ssl,
                                        (const unsigned char *)buf + written,
                                        len - written);
            if (ret > 0) {
                written += ret;
            } else if (ret == MBEDTLS_ERR_SSL_WANT_READ || ret == MBEDTLS_ERR_SSL_WANT_WRITE) {
                if (time(NULL) - start >= NET_TIMEOUT_SEC) {
                    printf("[airScanner] SSL send timeout\n");
                    net_timeout_hit = 1;
                    return -1;
                }
                wait_socket((unsigned int)sec->sock,
                            ret == MBEDTLS_ERR_SSL_WANT_READ,
                            ret == MBEDTLS_ERR_SSL_WANT_WRITE, 100);
            } else {
                printf("[airScanner] SSL write error: -0x%04x\n", -ret);
                return -1;
            }
        }
        return (int)len;
    }
    // Plain HTTP
    size_t sent = 0;
    time_t start = time(NULL);
    while (sent < len) {
        int r = send(sec->sock, (const char *)buf + sent, len - sent, 0);
        if (r > 0) {
            sent += (size_t)r;
            continue;
        }
        if (r < 0 && errno != EAGAIN && errno != EWOULDBLOCK && errno != EINTR) {
            return -1;
        }
        time_t elapsed = time(NULL) - start;
        if (elapsed >= NET_TIMEOUT_SEC) {
            net_timeout_hit = 1;
            return -1;
        }
        int wait_sec = (int)(NET_TIMEOUT_SEC - elapsed);
        if (wait_sec > 1) wait_sec = 1;
        if (wait_sec < 1) wait_sec = 1;
        fd_set wfds;
        struct timeval tv;
        FD_ZERO(&wfds);
        FD_SET(sec->sock, &wfds);
        tv.tv_sec = wait_sec;
        tv.tv_usec = 0;
        int s = select(sec->sock + 1, NULL, &wfds, NULL, &tv);
        if (s < 0) {
            if (errno == EINTR) continue;
            return -1;
        }
    }
    return (int)sent;
}

int sec_recv(SecureConnection *sec, void *buf, size_t len) {
    if (sec->use_ssl) {
        time_t start = time(NULL);
        for (;;) {
            int ret = mbedtls_ssl_read(&sec->ssl, (unsigned char *)buf, len);
            if (ret > 0) return ret;
            if (ret == MBEDTLS_ERR_SSL_WANT_READ || ret == MBEDTLS_ERR_SSL_WANT_WRITE) {
                if (time(NULL) - start >= NET_TIMEOUT_SEC) {
                    net_timeout_hit = 1;
                    return -1;
                }
                wait_socket((unsigned int)sec->sock,
                            ret == MBEDTLS_ERR_SSL_WANT_READ,
                            ret == MBEDTLS_ERR_SSL_WANT_WRITE, 100);
                continue;
            }
            if (ret == MBEDTLS_ERR_SSL_PEER_CLOSE_NOTIFY) {
                printf("[airScanner] SSL peer closed\n");
                return 0;
            }
            if (ret < 0) {
                printf("[airScanner] SSL read error: -0x%04x\n", -ret);
                return -1;
            }
            return 0;
        }
    }
    // Plain HTTP
    time_t start = time(NULL);
    for (;;) {
        int r = recv(sec->sock, buf, len, 0);
        if (r > 0) return r;
        if (r == 0) return 0;
        if (errno != EAGAIN && errno != EWOULDBLOCK && errno != EINTR) {
            return -1;
        }
        time_t elapsed = time(NULL) - start;
        if (elapsed >= NET_TIMEOUT_SEC) {
            net_timeout_hit = 1;
            return -1;
        }
        int wait_sec = (int)(NET_TIMEOUT_SEC - elapsed);
        if (wait_sec > 1) wait_sec = 1;
        if (wait_sec < 1) wait_sec = 1;
        fd_set rfds;
        struct timeval tv;
        FD_ZERO(&rfds);
        FD_SET(sec->sock, &rfds);
        tv.tv_sec = wait_sec;
        tv.tv_usec = 0;
        int s = select(sec->sock + 1, &rfds, NULL, NULL, &tv);
        if (s == 0) {
            if (time(NULL) - start >= NET_TIMEOUT_SEC) {
                net_timeout_hit = 1;
                return -1;
            }
            continue;
        }
        if (s < 0 && errno != EINTR) return -1;
    }
}

void sec_close(SecureConnection *sec) {
    if (sec) {
        if (sec->use_ssl) {
            mbedtls_ssl_close_notify(&sec->ssl);
            mbedtls_ssl_free(&sec->ssl);
            mbedtls_ssl_config_free(&sec->conf);
            mbedtls_ctr_drbg_free(&sec->ctr_drbg);
            mbedtls_entropy_free(&sec->entropy);
        }
        close(sec->sock);
        free(sec);
    }
}

/* --- eSCL LOGIC --- */

int get_xml_tag_value(const char *xml, const char *tag_name, char *dest, size_t max_len) {
    const char *prefixes[] = {"<pwg:", "<scan:", "<escl:", "<", NULL};
    char search_tag[64];

    for (int i = 0; prefixes[i] != NULL; i++) {
        snprintf(search_tag, sizeof(search_tag), "%s%s", prefixes[i], tag_name);
        char *start = strstr(xml, search_tag);
        
        if (start) {
            start = strchr(start, '>');
            if (start) {
                start++; 
                char *end = strchr(start, '<');
                if (end && end > start) {
                    size_t len = end - start;
                    if (len >= max_len) len = max_len - 1;
                    strncpy(dest, start, len);
                    dest[len] = '\0';
                    return 1;
                }
            }
        }
    }
    return 0;
}

static void probe_plaintext_http(const char *host, int port, int from_ssl) {
    /* Diagnostic: send a plaintext HTTP request straight to the port.
       Distinguishes HTTPS (TLS server, replies with TLS/garbage/refuse)
       from a plain HTTP endpoint (would answer 200). */
    struct hostent *he = gethostbyname(host);
    if (!he) {
        printf("[airScanner] probe: cannot resolve %s\n", host);
        return;
    }

    int sock = socket(AF_INET, SOCK_STREAM, 0);
    if (sock < 0) return;

    int on = 1;
    ioctl(sock, FIONBIO, &on);

    struct sockaddr_in server;
    server.sin_family = AF_INET;
    server.sin_port = htons(port);
    server.sin_addr = *((struct in_addr *)he->h_addr);

    if (connect(sock, (struct sockaddr *)&server, sizeof(server)) < 0) {
        fd_set wfds;
        struct timeval tv;
        FD_ZERO(&wfds);
        FD_SET(sock, &wfds);
        tv.tv_sec = NET_TIMEOUT_SEC;
        tv.tv_usec = 0;
        if (select(sock + 1, NULL, &wfds, NULL, &tv) <= 0) {
            printf("[airScanner] probe: cannot connect to %s:%d\n", host, port);
            close(sock);
            return;
        }
        int conn_err = 0;
        socklen_t elen = sizeof(conn_err);
        if (getsockopt(sock, SOL_SOCKET, SO_ERROR, &conn_err, &elen) < 0 || conn_err != 0) {
            printf("[airScanner] probe: connect error %d on %s:%d\n", conn_err, host, port);
            close(sock);
            return;
        }
    }
    on = 0;
    ioctl(sock, FIONBIO, &on);

    char req[192];
    snprintf(req, sizeof(req),
        "GET /eSCL/ScannerCapabilities HTTP/1.1\r\n"
        "Host: %s\r\n"
        "User-Agent: Mozilla/5.0\r\n"
        "Connection: close\r\n\r\n", host);
    send(sock, req, strlen(req), 0);

    char rbuf[1024] = {0};
    int total = 0, n;
    while (total < (int)sizeof(rbuf) - 1 &&
           (n = recv(sock, rbuf + total, sizeof(rbuf) - total - 1, 0)) > 0) {
        total += n;
    }
    close(sock);

    printf("[airScanner] probe (plaintext HTTP on %s:%d after TLS %s): %d bytes\n",
           host, port, from_ssl ? "failure" : "test", total);
    if (total > 0)
        printf("[airScanner] probe head: %.384s\n", rbuf);
    else
        printf("[airScanner] probe: no plaintext response on that port.\n");
}

static int fetch_eSCL_capabilities(const char *url_str, char *buf, size_t size) {
    SecureConnection *sec = sec_connect(url_str);
    if (!sec) return -1;

    char host[128];
    int port, use_ssl;
    parse_scanner_url(url_str, host, sizeof(host), &port, &use_ssl);

    char request[256];
    snprintf(request, sizeof(request), 
        "GET /eSCL/ScannerCapabilities HTTP/1.1\r\n"
        "Host: %s\r\n"
        "User-Agent: Mozilla/5.0\r\n"
        "Accept: */*\r\n"
        "Connection: close\r\n\r\n", host);
        
    net_timeout_hit = 0;
    if (sec_send(sec, request, strlen(request)) < 0) {
        sec_close(sec);
        if (use_ssl) probe_plaintext_http(host, port, 1);
        return -1;
    }

    int total = 0, n;
    while ((n = sec_recv(sec, buf + total, size - total - 1)) > 0) {
        total += n;
        if (total >= (int)size - 1) break;
    }
    sec_close(sec);
    if (n < 0) {
        printf("[airScanner] Capabilities fetch: read error, read_timeout=%s\n",
               net_timeout_hit ? "YES" : "NO");
        if (use_ssl) probe_plaintext_http(host, port, 1);
        return -1;
    }
    if (total == 0) {
        printf("[airScanner] Capabilities fetch: 0 bytes received, "
               "read_timeout=%s\n", net_timeout_hit ? "YES" : "NO");
        if (use_ssl) probe_plaintext_http(host, port, 1);
    }
    return total;
}

void CheckScannerCapabilities() {
    IPTR ip_ptr;
    get(str_ip, MUIA_String_Contents, &ip_ptr);
    const char *url_str = (const char *)ip_ptr;

    if (!url_str || strlen(url_str) == 0) return;
    set(txt_status, MUIA_Text_Contents, (IPTR)"Searching for scanner (HTTP/HTTPS)...");

    char buf[65536] = {0}; 
    int total = fetch_eSCL_capabilities(url_str, buf, sizeof(buf));
    char effective_url[160];
    strncpy(effective_url, url_str, sizeof(effective_url) - 1);
    effective_url[sizeof(effective_url) - 1] = '\0';

    if (total <= 0) {
        char host[128]; int port, use_ssl;
        parse_scanner_url(url_str, host, sizeof(host), &port, &use_ssl);
        if (use_ssl) {
            set(txt_status, MUIA_Text_Contents, (IPTR)"TLS failed, retrying plain HTTP on same port...");
            char fallback[160];
            snprintf(fallback, sizeof(fallback), "http://%s:%d", host, port);
            total = fetch_eSCL_capabilities(fallback, buf, sizeof(buf));
            if (total > 0) {
                strncpy(effective_url, fallback, sizeof(effective_url) - 1);
                effective_url[sizeof(effective_url) - 1] = '\0';
                set(str_ip, MUIA_String_Contents, (IPTR)effective_url);
                set(txt_status, MUIA_Text_Contents, (IPTR)"Connected via plain HTTP on TLS port (TLS failed).");
            }
        }
        if (total <= 0 && port != 80) {
            set(txt_status, MUIA_Text_Contents, (IPTR)"Trying plain HTTP on standard port 80...");
            char fallback[160];
            snprintf(fallback, sizeof(fallback), "http://%s", host);
            int t80 = fetch_eSCL_capabilities(fallback, buf, sizeof(buf));
            if (t80 > 0) {
                total = t80;
                strncpy(effective_url, fallback, sizeof(effective_url) - 1);
                effective_url[sizeof(effective_url) - 1] = '\0';
                set(str_ip, MUIA_String_Contents, (IPTR)effective_url);
                set(txt_status, MUIA_Text_Contents, (IPTR)"Connected via plain HTTP on port 80.");
            }
        }
    }

    if (total < 0) {
        set(txt_status, MUIA_Text_Contents, (IPTR)"Error: Cannot connect to scanner.");
        return;
    }

    printf("\n[airScanner] Raw response length: %d bytes\n", total);
    if (total > 0) {
        printf("[airScanner] --- Response head (first 2000 bytes) ---\n%.*s\n[airScanner] --- end ---\n", total < 2000 ? total : 2000, buf);
    }
    
    if (strncmp(buf, "HTTP/1.", 7) == 0) {
        int http_code = atoi(buf + 9);
        if (http_code != 200) {
            char status_err[128];
            snprintf(status_err, sizeof(status_err), "Scanner returned HTTP %d", http_code);
            set(txt_status, MUIA_Text_Contents, (IPTR)status_err);
            return;
        }
    }

    char model_name[128] = {0};
    char host[128]; int port, use_ssl = 0;
    parse_scanner_url(effective_url, host, sizeof(host), &port, &use_ssl);
    if (get_xml_tag_value(buf, "MakeAndModel", model_name, sizeof(model_name)) ||
        get_xml_tag_value(buf, "Model", model_name, sizeof(model_name))) {
        
        char status_msg[256];
        snprintf(status_msg, sizeof(status_msg), "Found: %s (TLS: %s)", model_name, use_ssl ? "Yes" : "No");
        set(txt_status, MUIA_Text_Contents, (IPTR)status_msg);
        set(btn_scan, MUIA_Disabled, FALSE);
        return;
    }
    
    if (total > 0 && strstr(buf, "200 OK")) {
        set(txt_status, MUIA_Text_Contents, (IPTR)"Scanner ready (generic model).");
        set(btn_scan, MUIA_Disabled, FALSE);
        return;
    }
    
    set(txt_status, MUIA_Text_Contents, (IPTR)"Model not recognized.");
}

void PerformScan() {
    IPTR ip_ptr, dpi_idx;
    get(str_ip, MUIA_String_Contents, &ip_ptr);
    get(cyc_dpi, MUIA_Cycle_Active, &dpi_idx);
    
    const char *url_str = (const char *)ip_ptr;
    char scan_url_buf[160];
    strncpy(scan_url_buf, url_str ? url_str : "", sizeof(scan_url_buf) - 1);
    scan_url_buf[sizeof(scan_url_buf) - 1] = '\0';
    const char *scan_url = scan_url_buf;
    int dpi = (dpi_idx == 0) ? 100 : 300;

    char host[128];
    int port, use_ssl;
    parse_scanner_url(scan_url, host, sizeof(host), &port, &use_ssl);

    set(txt_status, MUIA_Text_Contents, (IPTR)"Starting scan task...");
    
    char xml_payload[1024];
    snprintf(xml_payload, sizeof(xml_payload),
        "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\r\n"
        "<scan:ScanSettings xmlns:pwg=\"http://www.pwg.org/schemas/2010/12/sm\" xmlns:scan=\"http://schemas.hp.com/imaging/escl/2011/05/03\">\r\n"
        "<pwg:Version>2.0</pwg:Version>\r\n"
        "<scan:Intent>Document</scan:Intent>\r\n"
        "<scan:InputSource>Platen</scan:InputSource>\r\n"
        "<scan:ColorMode>RGB24</scan:ColorMode>\r\n"
        "<scan:XResolution>%d</scan:XResolution>\r\n"
        "<scan:YResolution>%d</scan:YResolution>\r\n"
        "<pwg:DocumentFormat>image/jpeg</pwg:DocumentFormat>\r\n"
        "</scan:ScanSettings>\r\n", dpi, dpi);

    SecureConnection *sec = sec_connect(scan_url);
    if (!sec && use_ssl) {
        // The Epson server also answers plaintext HTTP on port 443.
        char plain_url[160];
        snprintf(plain_url, sizeof(plain_url), "http://%s:%d", host, port);
        sec = sec_connect(plain_url);
        if (sec) {
            strncpy(scan_url_buf, plain_url, sizeof(scan_url_buf) - 1);
            scan_url_buf[sizeof(scan_url_buf) - 1] = '\0';
            scan_url = scan_url_buf;
            set(str_ip, MUIA_String_Contents, (IPTR)scan_url);
            parse_scanner_url(scan_url, host, sizeof(host), &port, &use_ssl);
        }
    }
    if (!sec) {
        set(txt_status, MUIA_Text_Contents, (IPTR)"Error: Cannot connect to scanner.");
        return;
    }

    char request[2048];
    snprintf(request, sizeof(request),
        "POST /eSCL/ScanJobs HTTP/1.1\r\n"
        "Host: %s\r\n"
        "User-Agent: Mozilla/5.0\r\n"
        "Content-Type: text/xml\r\n"
        "Content-Length: %d\r\n"
        "Expect:\r\n"
        "Connection: close\r\n\r\n"
        "%s", host, (int)strlen(xml_payload), xml_payload);
        
    net_timeout_hit = 0;
    if (sec_send(sec, request, strlen(request)) < 0) {
        set(txt_status, MUIA_Text_Contents, (IPTR)"Error: TLS write failed during scan.");
        sec_close(sec);
        return;
    }

    char buf[2048] = {0};
    int total = 0, n;
    while ((n = sec_recv(sec, buf + total, sizeof(buf) - total - 1)) > 0) {
        total += n;
    }
    sec_close(sec);
    if (n < 0) {
        set(txt_status, MUIA_Text_Contents, (IPTR)"Error: Connection read failed during ScanJobs.");
        return;
    }

    char *loc = strstr(buf, "Location:");
    if (!loc) loc = strstr(buf, "location:");

    if (loc) {
        loc += 9;
        while (*loc == ' ') loc++;
        char *end = strpbrk(loc, "\r\n");
        if (end) *end = '\0';

        // Extract path avoiding the domain to reuse our secure connection config
        char path[256] = {0};
        if (strncmp(loc, "http://", 7) == 0) {
            char *p = strchr(loc + 7, '/');
            if (p) strncpy(path, p, sizeof(path) - 1);
        } else if (strncmp(loc, "https://", 8) == 0) {
            char *p = strchr(loc + 8, '/');
            if (p) strncpy(path, p, sizeof(path) - 1);
        } else {
            strncpy(path, loc, sizeof(path) - 1);
        }

        {
            const char *suffix = "NextDocument";
            size_t plen = strlen(path);
            size_t slen = strlen(suffix);
            if (plen == 0) {
                if (snprintf(path, sizeof(path), "/%s", suffix) >= (int)sizeof(path)) {
                    set(txt_status, MUIA_Text_Contents, (IPTR)"Error: Scanner path too long.");
                    return;
                }
            } else if (path[plen - 1] == '/') {
                if (plen + slen >= sizeof(path)) {
                    set(txt_status, MUIA_Text_Contents, (IPTR)"Error: Scanner path too long.");
                    return;
                }
                strncat(path, suffix, sizeof(path) - strlen(path) - 1);
            } else {
                if (plen + 1 + slen >= sizeof(path)) {
                    set(txt_status, MUIA_Text_Contents, (IPTR)"Error: Scanner path too long.");
                    return;
                }
                strncat(path, "/", sizeof(path) - strlen(path) - 1);
                strncat(path, suffix, sizeof(path) - strlen(path) - 1);
            }
        }

        set(txt_status, MUIA_Text_Contents, (IPTR)"Scanning... (waiting for file)");
        sleep(3);

        SecureConnection *sec2 = sec_connect(scan_url);
        if (!sec2 && use_ssl) {
            char plain_url[160];
            snprintf(plain_url, sizeof(plain_url), "http://%s:%d", host, port);
            sec2 = sec_connect(plain_url);
            if (sec2) {
                strncpy(scan_url_buf, plain_url, sizeof(scan_url_buf) - 1);
                scan_url_buf[sizeof(scan_url_buf) - 1] = '\0';
                scan_url = scan_url_buf;
                set(str_ip, MUIA_String_Contents, (IPTR)scan_url);
                parse_scanner_url(scan_url, host, sizeof(host), &port, &use_ssl);
            }
        }
        if (sec2) {
            snprintf(request, sizeof(request), 
                "GET %s HTTP/1.1\r\n"
                "Host: %s\r\n"
                "User-Agent: Mozilla/5.0\r\n"
                "Connection: close\r\n\r\n", path, host);
                
            net_timeout_hit = 0;
            if (sec_send(sec2, request, strlen(request)) < 0) {
                set(txt_status, MUIA_Text_Contents, (IPTR)"Error: TLS write failed during download.");
                sec_close(sec2);
                return;
            }

            FILE *fp = fopen("RAM:scan.jpg", "wb");
            if (fp) {
                char c;
                int state = 0;
                int body_bytes = 0;
                int read_err = 0;
                while (sec_recv(sec2, &c, 1) == 1) {
                    if (c == '\r' && (state == 0 || state == 2)) state++;
                    else if (c == '\n' && state == 1) state++;
                    else if (c == '\n' && state == 3) { state = 4; break; }
                    else state = 0;
                }

                if (state == 4) {
                    char chunk[4096];
                    while ((n = sec_recv(sec2, chunk, sizeof(chunk))) > 0) {
                        fwrite(chunk, 1, n, fp);
                        body_bytes += n;
                    }
                    if (n < 0) read_err = 1;
                }
                fclose(fp);
                if (read_err) {
                    set(txt_status, MUIA_Text_Contents, (IPTR)"Error: Connection read failed during download.");
                } else if (state == 4 && body_bytes > 0) {
                    set(txt_status, MUIA_Text_Contents, (IPTR)"Done! Saved as RAM:scan.jpg");
                } else {
                    set(txt_status, MUIA_Text_Contents, (IPTR)"Error: No image data returned by scanner.");
                }
            } else {
                set(txt_status, MUIA_Text_Contents, (IPTR)"Error: Cannot create file in RAM:");
            }
            sec_close(sec2);
        } else {
            set(txt_status, MUIA_Text_Contents, (IPTR)"Error: Reconnection for download failed.");
        }
    } else {
        set(txt_status, MUIA_Text_Contents, (IPTR)"Error: Bad scanner response (missing Location).");
    }
}

int main(int argc, char *argv[]) {
    // 0. kernel.resource base, needed by the AROS mbedTLS hardware entropy source
    KernelBase = OpenResource("kernel.resource");

    // 1. Initialize Network
    SocketBase = OpenLibrary("network.library", 0);
    if (!SocketBase) SocketBase = OpenLibrary("bsdsocket.library", 4);
    if (!SocketBase) {
        fprintf(stderr, "Error: No TCP/IP stack.\n");
        return 20;
    }

    // 2. Initialize MUI
    MUIMasterBase = OpenLibrary("muimaster.library", 19);
    if (!MUIMasterBase) {
        fprintf(stderr, "Error: Cannot open muimaster.library.\n");
        CloseLibrary(SocketBase);
        return 20;
    }

    // 3. Initialize mbedTLS (no special init needed, handled per-connection)

    static const char *dpi_array[] = {"100 DPI", "300 DPI", NULL};

    app = ApplicationObject,
        MUIA_Application_Title, "airScanner Lite TLS",
        MUIA_Application_Version, "$VER: airScanner Lite TLS 0.3",
        SubWindow, window = WindowObject,
            MUIA_Window_Title, "airScanner Lite TLS",
            MUIA_Window_ID, MAKE_ID('M','A','I','N'),
            MUIA_Window_RootObject, VGroup,
                Child, HGroup,
                    Child, Label2("Scanner URL:"),
                    Child, str_ip = StringObject, 
                        MUIA_String_Contents, "https://192.168.0.69", 
                        MUIA_String_MaxLen, 64, 
                    End,
                    Child, btn_conn = SimpleButton("Connect"),
                End,
                Child, HGroup,
                    Child, Label2("Status:"),
                    Child, txt_status = TextObject, 
                        MUIA_Text_Contents, "Ready. Enter URL (http/https) and Connect.", 
                        MUIA_Text_PreParse, "\33b", 
                    End,
                End,
                Child, HGroup,
                    Child, Label2("Resolution:"),
                    Child, cyc_dpi = CycleObject, 
                        MUIA_Cycle_Entries, dpi_array, 
                    End,
                    Child, btn_scan = SimpleButton("Scan to RAM:scan.jpg"),
                End,
            End,
        End,
    End;

    if (!app) {
        fprintf(stderr, "Error: Failed to create GUI.\n");
        CloseLibrary(MUIMasterBase);
        CloseLibrary(SocketBase);
        return 20;
    }

    set(btn_scan, MUIA_Disabled, TRUE);
    DoMethod(window, MUIM_Notify, MUIA_Window_CloseRequest, TRUE, app, 2, MUIM_Application_ReturnID, ID_QUIT);
    DoMethod(btn_conn, MUIM_Notify, MUIA_Pressed, FALSE, app, 2, MUIM_Application_ReturnID, ID_CONNECT);
    DoMethod(btn_scan, MUIM_Notify, MUIA_Pressed, FALSE, app, 2, MUIM_Application_ReturnID, ID_SCAN);
    set(window, MUIA_Window_Open, TRUE);

    ULONG signals = 0;
    BOOL running = TRUE;

    while (running) {
        ULONG id = DoMethod(app, MUIM_Application_NewInput, &signals);

        switch (id) {
            case ID_QUIT: running = FALSE; break;
            case ID_CONNECT: CheckScannerCapabilities(); break;
            case ID_SCAN: PerformScan(); break;
        }

        if (running && signals) {
            signals = Wait(signals | SIGBREAKF_CTRL_C);
            if (signals & SIGBREAKF_CTRL_C) running = FALSE;
        }
    }

    set(window, MUIA_Window_Open, FALSE);
    MUI_DisposeObject(app);
    CloseLibrary(MUIMasterBase);
    CloseLibrary(SocketBase);

    return 0;
}