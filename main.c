/*
 * airScanner Lite - C Port for AROS (aarch64 / x86_64)
 * Dependency-free version with HTTP / HTTPS (TLS via BearSSL)
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
#include <arpa/inet.h>
#include <netdb.h>

#include <bearssl.h> /* BearSSL Header */

#include <proto/exec.h>
#include <proto/intuition.h>
#include <proto/muimaster.h>
#include <proto/alib.h>        
#include <proto/dos.h>
#include <dos/dos.h>        
#include <libraries/mui.h>
#include <workbench/startup.h>

#define NET_TIMEOUT_SEC 30
#define SSL_MAX_TRACE 8192

/* Global MUI and System pointers */
struct Library *MUIMasterBase = NULL;
struct Library *SocketBase = NULL;
Object *app, *window, *str_ip, *txt_status, *cyc_dpi, *btn_conn, *btn_scan;
static char scanner_url_effective[160] = {0};

#define ID_QUIT     1
#define ID_CONNECT  2
#define ID_SCAN     3

/* --- TLS / SECURE CONNECTION WRAPPER --- */

typedef struct {
    int sock;
    int use_ssl;
    br_ssl_client_context sc;
    br_x509_minimal_context xc;
    br_sslio_context ioc;
    unsigned char iobuf[BR_SSL_BUFSIZE_BIDI];
} SecureConnection;

// BearSSL I/O Callbacks
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

static int sock_read(void *ctx, unsigned char *buf, size_t len) {
    int fd = *(int *)ctx;
    // Socket is left in non-blocking mode, so we can poll recv() directly
    // every ~200 ms without trusting select()/FIONREAD (which AROS's
    // bsdsocket can misreport for back-to-back bursts, e.g. the scanner
    // sending the last 268 bytes of the Certificate record).
    time_t start = time(NULL);
    int attempts = 0;
    for (;;) {
        int r = recv(fd, buf, len, 0);
        if (r > 0) {
            if (ssl_trace) {
                ssl_bytes_in += r;
                if (ssl_bytes_in <= SSL_MAX_TRACE) hexdump("RX", buf, r);
            }
            return r;
        }
        if (r == 0) return -1; /* EOF */
        if (r < 0 && errno != EAGAIN && errno != EWOULDBLOCK && errno != EINTR) {
            return -1;
        }
        attempts++;
        if (attempts == 1 || attempts % 75 == 0) { /* ~15 s between beats */
            printf("[airScanner] waiting for %lu bytes (%d attempts)\n",
                   (unsigned long)len, attempts);
            fflush(stdout);
        }
        if (time(NULL) - start >= NET_TIMEOUT_SEC) {
            unsigned char peekbuf[16];
            unsigned long fin = 0;
            ioctl(fd, FIONREAD, &fin);
            memset(peekbuf, 0, sizeof(peekbuf));
            int pr = recv(fd, peekbuf, (int)(len < sizeof(peekbuf) ? len : sizeof(peekbuf)),
                          MSG_PEEK);
            printf("[airScanner] read TIMEOUT: want=%lu FIONREAD=%lu peek=%d errno=%d\n",
                   (unsigned long)len, (unsigned long)fin, pr, errno);
            net_timeout_hit = 1;
            return -1;
        }
        Delay(10); /* ~200 ms on AROS (50 Hz tick) */
    }
}

static int sock_write(void *ctx, const unsigned char *buf, size_t len) {
    int fd = *(int *)ctx;
    // Fully non-blocking send pump: send what fits, wait for writability,
    // loop until everything is written or the timeout elapses.
    size_t sent = 0;
    time_t start = time(NULL);
    while (sent < len) {
        int r = send(fd, buf + sent, len - sent, 0);
        if (r > 0) {
            sent += (size_t)r;
            if (ssl_trace) {
                ssl_bytes_out += r;
                if (ssl_bytes_out <= SSL_MAX_TRACE) hexdump("TX", buf, r);
            }
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
        FD_SET(fd, &wfds);
        tv.tv_sec = wait_sec;
        tv.tv_usec = 0;
        if (select(fd + 1, NULL, &wfds, NULL, &tv) < 0) {
            net_timeout_hit = 1;
            return -1;
        }
    }
    return (int)sent;
}

// Custom BearSSL X509 VTable to ignore Self-Signed certificate errors
static br_x509_class insecure_x509_vtable;

static unsigned insecure_end_chain(const br_x509_class **ctx) {
    unsigned r = br_x509_minimal_vtable.end_chain(ctx);
    (void)r;
    // The Epson's self-signed cert is signed with SHA-1, so the "sane"
    // minimal profile records an error during append_chain/end_chain and
    // drops the parsed key (get_pkey() returns NULL -> key type 0 ->
    // engine error BR_ERR_UNEXPECTED).  Force the "not trusted" state so
    // BearSSL still publishes the public key we need for ServerKeyExchange.
    br_x509_minimal_context *xc = (br_x509_minimal_context *)(void *)ctx;
    if (xc->err != BR_ERR_X509_OK) {
        xc->err = BR_ERR_X509_NOT_TRUSTED;
    }
    return 0; // 0 = Force success, ignore validation errors
}

static void init_insecure_x509() {
    memcpy(&insecure_x509_vtable, &br_x509_minimal_vtable, sizeof(br_x509_class));
    insecure_x509_vtable.end_chain = insecure_end_chain;
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

// Inject non-OS entropy into the engine (no /dev/urandom on AROS)
static void fill_entropy(unsigned char *buf, size_t len) {
    unsigned long x = (unsigned long)time(NULL) ^ (unsigned long)(unsigned long)&buf ^ 0x9E3779B9UL;
    size_t i = 0;
    while (i < len) {
        x ^= x << 13; x ^= x >> 17; x ^= x << 5; /* xorshift */
        buf[i++] = (unsigned char)(x >> 24);
        if (i >= len) break;
        buf[i++] = (unsigned char)(x >> 16);
        if (i >= len) break;
        buf[i++] = (unsigned char)(x >> 8);
        if (i >= len) break;
        buf[i++] = (unsigned char)x;
    }
}

static void init_ssl_rng(SecureConnection *sec) {
    unsigned char seed[32];
    fill_entropy(seed, sizeof(seed));
    br_ssl_engine_inject_entropy(&sec->sc.eng, seed, sizeof(seed));
}

static int is_ip_addr(const char *s) {
    unsigned int a, b, c, d;
    char tail;
    if (sscanf(s, "%u.%u.%u.%u%c", &a, &b, &c, &d, &tail) != 4) return 0;
    return a < 256 && b < 256 && c < 256 && d < 256;
}

// Establish Secure or Plain connection
SecureConnection* sec_connect(const char *url_str) {
    char host[128];
    int port, use_ssl;
    parse_scanner_url(url_str, host, sizeof(host), &port, &use_ssl);

    struct hostent *he = gethostbyname(host);
    if (!he) return NULL;

    int sock = socket(AF_INET, SOCK_STREAM, 0);
    if (sock < 0) return NULL;

    // Give the receive window enough room for the whole TLS flight.
    // The Epson sends its certificate in one burst; a small default
    // SO_RCVBUF would let the scanner fill the window and then abort
    // the connection when it cannot push the rest (we saw exactly that:
    // EOF after 597 of 865 certificate bytes).
    {
        int rbuf = 65536;
        int sbuf = 65536;
        setsockopt(sock, SOL_SOCKET, SO_RCVBUF, &rbuf, sizeof(rbuf));
        setsockopt(sock, SOL_SOCKET, SO_SNDBUF, &sbuf, sizeof(sbuf));
    }

    unsigned long on = 1;
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
            return NULL;
        }
        int conn_err = 0;
        socklen_t elen = sizeof(conn_err);
        if (getsockopt(sock, SOL_SOCKET, SO_ERROR, &conn_err, &elen) < 0 || conn_err != 0) {
            close(sock);
            return NULL;
        }
    }
    // Socket stays in non-blocking mode; sock_read()/sock_write() poll it.
    SecureConnection *sec = malloc(sizeof(SecureConnection));
    if (!sec) { close(sock); return NULL; }
    memset(sec, 0, sizeof(SecureConnection));
    
    sec->sock = sock;
    sec->use_ssl = use_ssl;

    if (use_ssl) {
        br_ssl_client_init_full(&sec->sc, &sec->xc, NULL, 0);
        init_ssl_rng(sec);
        // Offer TLS 1.2 suites only (drop TLS 1.3 cipher suites CCA8/CCA9,
        // which must not appear without the supported_versions extension;
        // the Epson embedded TLS stack stalls on such a ClientHello).
        {
            static const uint16_t tls12_suites[] = {
                0xC02B, 0xC02F, 0xC02C, 0xC030, 0xC0AC, 0xC0AD, 0xC0AE, 0xC0AF,
                0xC023, 0xC027, 0xC024, 0xC028, 0xC009, 0xC013, 0xC00A, 0xC014,
                0xC02D, 0xC031, 0xC02E, 0xC032, 0xC025, 0xC029, 0xC026, 0xC02A,
                0xC004, 0xC00E, 0xC005, 0xC00F, 0x009C, 0x009D, 0xC09C, 0xC09D,
                0xC0A0, 0xC0A1, 0x003C, 0x003D, 0x002F, 0x0035,
                0xC008, 0xC012, 0xC003, 0xC00D, 0x000A
            };
            br_ssl_engine_set_suites(&sec->sc.eng, tls12_suites,
                                     sizeof(tls12_suites) / sizeof(tls12_suites[0]));
        }
        sec->xc.vtable = &insecure_x509_vtable; // Bypass cert validation
        br_ssl_engine_set_buffer(&sec->sc.eng, sec->iobuf, sizeof(sec->iobuf), 1);
        // No SNI for IP-literal hosts (libcurl behaves the same way)
        br_ssl_client_reset(&sec->sc, is_ip_addr(host) ? NULL : host, 0);
        br_sslio_init(&sec->ioc, &sec->sc.eng, sock_read, &sec->sock, sock_write, &sec->sock);
        ssl_trace = 1;
        ssl_bytes_out = 0;
        ssl_bytes_in = 0;
        printf("[airScanner] TLS client started against %s:%d (ssl, timeout=%ds)\n",
               host, port, NET_TIMEOUT_SEC);
    }
    return sec;
}

int sec_send(SecureConnection *sec, const void *buf, size_t len) {
    if (sec->use_ssl) {
        if (br_sslio_write_all(&sec->ioc, buf, len) != 0) {
            int el = (int)br_ssl_engine_last_error(&sec->sc.eng);
            printf("[airScanner] SSL send failed, engine error=%d, timeout=%s\n",
                   el, net_timeout_hit ? "YES" : "NO");
            return -1;
        }
        return (int)len;
    }
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
        if (select(sec->sock + 1, NULL, &wfds, NULL, &tv) < 0) {
            net_timeout_hit = 1;
            return -1;
        }
    }
    return (int)sent;
}

int sec_recv(SecureConnection *sec, void *buf, size_t len) {
    if (sec->use_ssl) {
        int r = br_sslio_read(&sec->ioc, buf, len);
        if (r > 0) return r;
        if (r == 0) return 0;
        return -1;
    }
    time_t start = time(NULL);
    for (;;) {
        int r = recv(sec->sock, buf, len, 0);
        if (r > 0) return r;
        if (r == 0) return 0;
        if (errno != EAGAIN && errno != EWOULDBLOCK && errno != EINTR) {
            return -1;
        }
        if (time(NULL) - start >= NET_TIMEOUT_SEC) {
            net_timeout_hit = 1;
            return -1;
        }
        Delay(10);
    }
}

void sec_close(SecureConnection *sec) {
    if (sec) {
        if (sec->use_ssl) br_sslio_close(&sec->ioc);
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

    unsigned long on = 1;
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
    scanner_url_effective[0] = '\0';

    set(txt_status, MUIA_Text_Contents, (IPTR)"Searching for scanner (HTTP/HTTPS)...");

    char buf[65536] = {0}; 
    int total = fetch_eSCL_capabilities(url_str, buf, sizeof(buf));

    if ((total <= 0) && strncasecmp(url_str, "https", 5) == 0) {
        char host[128]; int port, use_ssl;
        parse_scanner_url(url_str, host, sizeof(host), &port, &use_ssl);
        char fallback[160];
        // The Epson web server also answers PLAINTEXT HTTP on its TLS port
        // (verified: HTTP/1.1 200 OK + full ScannerCapabilities on :443),
        // so fall back to plain HTTP on the SAME port rather than port 80.
        snprintf(fallback, sizeof(fallback), "http://%s:%d", host, port);
        set(txt_status, MUIA_Text_Contents, (IPTR)"TLS handshake failed, retrying plain HTTP...");
        total = fetch_eSCL_capabilities(fallback, buf, sizeof(buf));
        if (total > 0) {
            strncpy(scanner_url_effective, fallback, sizeof(scanner_url_effective) - 1);
            scanner_url_effective[sizeof(scanner_url_effective) - 1] = '\0';
            set(txt_status, MUIA_Text_Contents, (IPTR)"Connected via plain HTTP on TLS port (TLS failed).");
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

    if (total > 0 && scanner_url_effective[0] == '\0') {
        strncpy(scanner_url_effective, url_str, sizeof(scanner_url_effective) - 1);
        scanner_url_effective[sizeof(scanner_url_effective) - 1] = '\0';
    }

    char model_name[128] = {0};
    char host[128]; int port, use_ssl = 0;
    parse_scanner_url(scanner_url_effective[0] ? scanner_url_effective : url_str,
                      host, sizeof(host), &port, &use_ssl);
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
    const char *scan_url = scanner_url_effective[0] ? scanner_url_effective : url_str;
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

    // 3. Initialize BearSSL Insecure VTable
    init_insecure_x509();

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