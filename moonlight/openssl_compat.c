/*
 * VitaSDK 2026.08-20260815 ships libcurl built against the OpenSSL 1.0 API
 * together with OpenSSL 1.1.1 libraries. Keep the frozen toolchain usable by
 * forwarding only the legacy symbols referenced by that libcurl archive.
 */

#include <stddef.h>

typedef struct evp_md_ctx_st EVP_MD_CTX;
typedef struct ui_method_st UI_METHOD;
typedef struct ssl_method_st SSL_METHOD;
typedef struct stack_st OPENSSL_STACK;

EVP_MD_CTX *EVP_MD_CTX_new(void);
void EVP_MD_CTX_free(EVP_MD_CTX *context);
const UI_METHOD *UI_get_default_method(void);
unsigned long OpenSSL_version_num(void);
int OPENSSL_init_ssl(unsigned long options, const void *settings);
int OPENSSL_init_crypto(unsigned long options, const void *settings);
const SSL_METHOD *TLS_client_method(void);
int OPENSSL_sk_num(const OPENSSL_STACK *stack);
void *OPENSSL_sk_value(const OPENSSL_STACK *stack, int index);
void *OPENSSL_sk_pop(OPENSSL_STACK *stack);
void OPENSSL_sk_pop_free(OPENSSL_STACK *stack, void (*free_function)(void *));

EVP_MD_CTX *EVP_MD_CTX_create(void) { return EVP_MD_CTX_new(); }
void EVP_MD_CTX_destroy(EVP_MD_CTX *context) { EVP_MD_CTX_free(context); }
const UI_METHOD *UI_OpenSSL(void) { return UI_get_default_method(); }
unsigned long SSLeay(void) { return OpenSSL_version_num(); }
void EVP_cleanup(void) {}
void ENGINE_cleanup(void) {}
void ERR_free_strings(void) {}
void CONF_modules_free(void) {}
void SSL_COMP_free_compression_methods(void) {}
void SSL_load_error_strings(void) { (void)OPENSSL_init_ssl(0U, NULL); }
int SSL_library_init(void) { return OPENSSL_init_ssl(0U, NULL); }
void OPENSSL_add_all_algorithms_noconf(void) {
  (void)OPENSSL_init_crypto(0U, NULL);
}
const SSL_METHOD *SSLv23_client_method(void) { return TLS_client_method(); }
int sk_num(const OPENSSL_STACK *stack) { return OPENSSL_sk_num(stack); }
void *sk_value(const OPENSSL_STACK *stack, int index) {
  return OPENSSL_sk_value(stack, index);
}
void *sk_pop(OPENSSL_STACK *stack) { return OPENSSL_sk_pop(stack); }
void sk_pop_free(OPENSSL_STACK *stack, void (*free_function)(void *)) {
  OPENSSL_sk_pop_free(stack, free_function);
}
