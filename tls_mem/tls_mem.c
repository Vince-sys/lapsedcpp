#include <openssl/bio.h>
#include <openssl/err.h>
#include <openssl/ssl.h>

#include <assert.h>
#include <stdbool.h>
#include <stdio.h>
#include <string.h>

/* compile:
cmake -DCMAKE_BUILD_TYPE=Release . && cmake --build .
*/

#define UNUSED __attribute__((unused))

struct Endpoint {
    SSL_CTX *ctx;
    SSL *ssl;
    BIO *input;
    BIO *output;
};

void make_endpoint(const char *description, const bool is_server,
                   const SSL_METHOD *method, struct Endpoint *ep) {
    SSL_CTX *ctx = SSL_CTX_new(method);
    if (!ctx) {
        perror(description);
        ERR_print_errors_fp(stderr);
        exit(1);
    }

    SSL_CTX_set_min_proto_version(ctx, TLS1_2_VERSION);
    SSL_CTX_set_options(ctx, SSL_OP_ALL);
    SSL_CTX_set_default_verify_paths(ctx);

    if (is_server) {
        // made with:
        // openssl req -x509 -sha256 -nodes -days 365 -newkey rsa:2048 -keyout
        // ./tls_private_key.key -out ./tls_self_signed_certificate.crt
        SSL_CTX_use_certificate_file(ctx, "./tls_self_signed_certificate.crt",
                                     SSL_FILETYPE_PEM);
        SSL_CTX_use_PrivateKey_file(ctx, "./tls_private_key.key",
                                    SSL_FILETYPE_PEM);
        if (!SSL_CTX_check_private_key(ctx)) {
            perror("private key check");
            exit(1);
        }
    }

    memset(ep, 0, sizeof(struct Endpoint));
    ep->ctx = ctx;
    ep->ssl = SSL_new(ctx);

    if (is_server)
        SSL_set_accept_state(ep->ssl);
    else
        SSL_set_connect_state(ep->ssl);

    ep->input = BIO_new(BIO_s_mem());
    ep->output = BIO_new(BIO_s_mem());
    SSL_set_bio(ep->ssl, ep->input, ep->output);
}

bool ssl_wants_rw(SSL *ssl, int result_code) {
    int e = SSL_get_error(ssl, result_code);
    return e == SSL_ERROR_WANT_READ || e == SSL_ERROR_WANT_WRITE;
}

bool handshake_step(struct Endpoint *ep, const char *description) {
    if (SSL_is_init_finished(ep->ssl))
        return true;

    ERR_clear_error();
    int rs = SSL_do_handshake(ep->ssl);
    if (rs == 0 || (rs < 0 && !ssl_wants_rw(ep->ssl, rs))) {
        fprintf(stderr, "ERROR: %s handshake_step, return=%d, code=%d\n",
                description, rs, SSL_get_error(ep->ssl, rs));
        ERR_print_errors_fp(stderr);
        exit(1);
    }
    return rs == 1;
}

bool transfer(struct Endpoint *e1, struct Endpoint *e2,
              UNUSED const char *description_e1) {
    if (!BIO_pending(e1->output)) {
        return false;
    }
    size_t read;
    ERR_clear_error();
    char buffer[1024];
    int r = BIO_read_ex(e1->output, buffer, sizeof(buffer), &read);
    if (r >= 1) {
        size_t _written;
        BIO_write_ex(e2->input, buffer, read, &_written);
    }
    ERR_clear_error();
    return true;
}

int main() {
    OPENSSL_init_ssl(0, NULL);

    struct Endpoint server_ep;
    make_endpoint("server ctx", true, TLS_method(), &server_ep);
    struct Endpoint client_ep;
    make_endpoint("client ctx", false, TLS_method(), &client_ep);

    while (!SSL_is_init_finished(server_ep.ssl) ||
           !SSL_is_init_finished(client_ep.ssl)) {
        bool hss = handshake_step(&server_ep, "server");
        bool hsc = handshake_step(&client_ep, "client");
        if (!hss || !hsc || BIO_pending(server_ep.output) ||
            BIO_pending(client_ep.output)) {
            transfer(&client_ep, &server_ep, "client");
            transfer(&server_ep, &client_ep, "server");
        } else {
            fprintf(stderr,
                    "Handshake done but not? (server=%d,%d, client=%d,%d)\n",
                    hss, SSL_is_init_finished(server_ep.ssl), hsc,
                    SSL_is_init_finished(client_ep.ssl));
            exit(1);
        }
    }

    const char *server_msg = "Hello";
    const char *client_msg = "World";

    SSL_write(server_ep.ssl, server_msg, strlen(server_msg) + 1);
    SSL_write(client_ep.ssl, client_msg, strlen(client_msg) + 1);

    do {
        transfer(&client_ep, &server_ep, "client msg");
        transfer(&server_ep, &client_ep, "server msg");
    } while (BIO_pending(server_ep.output) || BIO_pending(client_ep.output));

    char msg_buf[128];
    {
        UNUSED int rr = SSL_read(client_ep.ssl, msg_buf, sizeof(msg_buf));
        assert(rr > 0);
        assert(strcmp(msg_buf, server_msg) == 0);
        printf("'%s' is good\n", msg_buf);
    }
    {
        UNUSED int rr = SSL_read(server_ep.ssl, msg_buf, sizeof(msg_buf));
        assert(rr > 0);
        assert(strcmp(msg_buf, client_msg) == 0);
        printf("'%s' is good\n", msg_buf);
    }

    return 0;
}
