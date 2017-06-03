
#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "php.h"
#include "php_openssl.h"

/* PHP Includes */
#include "ext/standard/info.h"
#include "ext/standard/md5.h"
#include "ext/standard/base64.h"

/* OpenSSL includes */
#include <openssl/evp.h>
#include <openssl/ssl.h>

#ifndef HAVE_OPENSSL_EXT
#define OPENSSL_ALGO_SHA1 	1
#define OPENSSL_ALGO_MD5	2
#define OPENSSL_ALGO_MD4	3
#ifdef HAVE_OPENSSL_MD2_H
#define OPENSSL_ALGO_MD2	4
#endif
#define OPENSSL_ALGO_DSS1	5
#if OPENSSL_VERSION_NUMBER >= 0x0090708fL
#define OPENSSL_ALGO_SHA224 6
#define OPENSSL_ALGO_SHA256 7
#define OPENSSL_ALGO_SHA384 8
#define OPENSSL_ALGO_SHA512 9
#define OPENSSL_ALGO_RMD160 10
#endif

enum php_openssl_cipher_type {
	PHP_OPENSSL_CIPHER_RC2_40,
	PHP_OPENSSL_CIPHER_RC2_128,
	PHP_OPENSSL_CIPHER_RC2_64,
	PHP_OPENSSL_CIPHER_DES,
	PHP_OPENSSL_CIPHER_3DES,
	PHP_OPENSSL_CIPHER_AES_128_CBC,
	PHP_OPENSSL_CIPHER_AES_192_CBC,
	PHP_OPENSSL_CIPHER_AES_256_CBC,

	PHP_OPENSSL_CIPHER_DEFAULT = PHP_OPENSSL_CIPHER_RC2_40
};
#endif


#if OPENSSL_VERSION_NUMBER >= 0x10100000L
# define _OPENSSL_CTX_REF(x) x
#else
# define _OPENSSL_CTX_REF(x) &(x)
#endif

typedef struct {
#if OPENSSL_VERSION_NUMBER >= 0x10100000L
	EVP_MD_CTX* md_ctx;
#else
	EVP_MD_CTX md_ctx;
#endif
	int complete;
	int siglen;
} php_openssl_digest_ctx;
typedef struct {
#if OPENSSL_VERSION_NUMBER >= 0x10100000L
	EVP_CIPHER_CTX* cipher_ctx;
#else
	EVP_CIPHER_CTX cipher_ctx;
#endif
	int complete;
	char* iv;
	unsigned char* key;
	int block_size;
} php_openssl_encdec_ctx;

#if PHP_MAJOR_VERSION > 5
typedef size_t php_strlen_t;
typedef zend_long php_long_t;
typedef zend_resource php_rsrc_t;
#define PHP_RETURN_STRINGL(s, l, c) RETVAL_STRINGL(s, l); if(!c) efree(s)
#define PHP_RETURN_RESOURCE(r, l) RETURN_RES(zend_register_resource(r, l))
#define PHP_ASSIGN_RESOURCE(target, type, zv, name, le) (target) = (type)zend_fetch_resource(Z_RES_P(zv), name, le)
#else
typedef int php_strlen_t;
typedef long php_long_t;
typedef zend_rsrc_list_entry php_rsrc_t;
#define PHP_RETURN_STRINGL RETVAL_STRINGL
#define PHP_RETURN_RESOURCE(r, l) ZEND_REGISTER_RESOURCE(return_value, r, l)
#define PHP_ASSIGN_RESOURCE(target, type, zv, name, le) ZEND_FETCH_RESOURCE(target, type, &(zv), -1, name, le)
#endif

PHP_FUNCTION(openssl_digest_init);
PHP_FUNCTION(openssl_digest_update);
PHP_FUNCTION(openssl_digest_final);
PHP_FUNCTION(openssl_encrypt_init);
PHP_FUNCTION(openssl_encrypt_update);
PHP_FUNCTION(openssl_encrypt_final);
PHP_FUNCTION(openssl_decrypt_init);
PHP_FUNCTION(openssl_decrypt_update);
PHP_FUNCTION(openssl_decrypt_final);

/* {{{ arginfo */

ZEND_BEGIN_ARG_INFO_EX(arginfo_openssl_digest_init, 0, 0, 1)
    ZEND_ARG_INFO(0, method)
ZEND_END_ARG_INFO()
ZEND_BEGIN_ARG_INFO_EX(arginfo_openssl_digest_update, 0, 0, 2)
    ZEND_ARG_INFO(0, ctx)
    ZEND_ARG_INFO(0, data)
ZEND_END_ARG_INFO()
ZEND_BEGIN_ARG_INFO_EX(arginfo_openssl_digest_final, 0, 0, 1)
    ZEND_ARG_INFO(0, ctx)
    ZEND_ARG_INFO(0, raw_output)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO_EX(arginfo_openssl_encrypt_init, 0, 0, 2)
    ZEND_ARG_INFO(0, method)
    ZEND_ARG_INFO(0, password)
    ZEND_ARG_INFO(0, options)
    ZEND_ARG_INFO(0, iv)
ZEND_END_ARG_INFO()
ZEND_BEGIN_ARG_INFO_EX(arginfo_openssl_encrypt_update, 0, 0, 2)
    ZEND_ARG_INFO(0, ctx)
    ZEND_ARG_INFO(0, data)
ZEND_END_ARG_INFO()
ZEND_BEGIN_ARG_INFO_EX(arginfo_openssl_encrypt_final, 0, 0, 1)
    ZEND_ARG_INFO(0, ctx)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO_EX(arginfo_openssl_decrypt_init, 0, 0, 2)
    ZEND_ARG_INFO(0, method)
    ZEND_ARG_INFO(0, password)
    ZEND_ARG_INFO(0, options)
    ZEND_ARG_INFO(0, iv)
ZEND_END_ARG_INFO()
ZEND_BEGIN_ARG_INFO_EX(arginfo_openssl_decrypt_update, 0, 0, 2)
    ZEND_ARG_INFO(0, ctx)
    ZEND_ARG_INFO(0, data)
ZEND_END_ARG_INFO()
ZEND_BEGIN_ARG_INFO_EX(arginfo_openssl_decrypt_final, 0, 0, 1)
    ZEND_ARG_INFO(0, ctx)
ZEND_END_ARG_INFO()


/* }}} */

/* {{{ openssl_functions[]
 */
const zend_function_entry openssl_functions[] = {

	PHP_FE(openssl_digest_init,				arginfo_openssl_digest_init)
	PHP_FE(openssl_digest_update,				arginfo_openssl_digest_update)
	PHP_FE(openssl_digest_final,				arginfo_openssl_digest_final)
	PHP_FE(openssl_encrypt_init,				arginfo_openssl_encrypt_init)
	PHP_FE(openssl_encrypt_update,				arginfo_openssl_encrypt_update)
	PHP_FE(openssl_encrypt_final,				arginfo_openssl_encrypt_final)
	PHP_FE(openssl_decrypt_init,				arginfo_openssl_decrypt_init)
	PHP_FE(openssl_decrypt_update,				arginfo_openssl_decrypt_update)
	PHP_FE(openssl_decrypt_final,				arginfo_openssl_decrypt_final)
	PHP_FE_END
};
/* }}} */

/* {{{ openssl_incr_module_entry
 */
zend_module_entry openssl_incr_module_entry = {
	STANDARD_MODULE_HEADER,
	"openssl_incr",
	openssl_functions,
	PHP_MINIT(openssl_incr),
#ifdef HAVE_OPENSSL_EXT
	NULL,
#else
	PHP_MSHUTDOWN(openssl_incr),
#endif
	NULL,
	NULL,
	PHP_MINFO(openssl_incr),
	NO_VERSION_YET,
	STANDARD_MODULE_PROPERTIES
};
/* }}} */

#ifdef COMPILE_DL_OPENSSL_INCR
ZEND_GET_MODULE(openssl_incr)
#endif

#define PHP_OPENSSL_CTX_DIGEST_NAME "OpenSSL digest context"
#define PHP_OPENSSL_CTX_ENCRYPT_NAME "OpenSSL encrypt context"
#define PHP_OPENSSL_CTX_DECRYPT_NAME "OpenSSL decrypt context"
static int le_digest;
static int le_encrypt;
static int le_decrypt;

/* {{{ resource destructors */
static void php_digest_free(php_rsrc_t *rsrc TSRMLS_DC)
{
	php_openssl_digest_ctx* ctx = (php_openssl_digest_ctx*)rsrc->ptr;
	
#if OPENSSL_VERSION_NUMBER >= 0x10100000L
	if(!ctx->complete) EVP_MD_CTX_free(ctx->md_ctx);
#else
	if(!ctx->complete) EVP_MD_CTX_cleanup(&(ctx->md_ctx));
#endif
	efree(ctx);
}

static void php_encdec_free(php_rsrc_t *rsrc TSRMLS_DC)
{
	php_openssl_encdec_ctx* ctx = (php_openssl_encdec_ctx*)rsrc->ptr;
	if(ctx->key) {
		efree(ctx->key);
		efree(ctx->iv);
	}
#if OPENSSL_VERSION_NUMBER >= 0x10100000L
	if(!ctx->complete) EVP_CIPHER_CTX_free(ctx->cipher_ctx);
#else
	if(!ctx->complete) EVP_CIPHER_CTX_cleanup(&(ctx->cipher_ctx));
#endif
	efree(ctx);
}

/* }}} */


/* {{{ PHP_MINIT_FUNCTION
 */
PHP_MINIT_FUNCTION(openssl_incr)
{
	le_digest = zend_register_list_destructors_ex(php_digest_free, NULL, PHP_OPENSSL_CTX_DIGEST_NAME, module_number);
	le_encrypt = zend_register_list_destructors_ex(php_encdec_free, NULL, PHP_OPENSSL_CTX_ENCRYPT_NAME, module_number);
	le_decrypt = zend_register_list_destructors_ex(php_encdec_free, NULL, PHP_OPENSSL_CTX_DECRYPT_NAME, module_number);

#ifndef HAVE_OPENSSL_EXT
	SSL_library_init();
	OpenSSL_add_all_ciphers();
	OpenSSL_add_all_digests();
	OpenSSL_add_all_algorithms();

	//SSL_load_error_strings();
	
	/* signature algorithm constants; assume already defined by OpenSSL extension */
	REGISTER_LONG_CONSTANT("OPENSSL_ALGO_SHA1", OPENSSL_ALGO_SHA1, CONST_CS|CONST_PERSISTENT);
	REGISTER_LONG_CONSTANT("OPENSSL_ALGO_MD5", OPENSSL_ALGO_MD5, CONST_CS|CONST_PERSISTENT);
	REGISTER_LONG_CONSTANT("OPENSSL_ALGO_MD4", OPENSSL_ALGO_MD4, CONST_CS|CONST_PERSISTENT);
#ifdef HAVE_OPENSSL_MD2_H
	REGISTER_LONG_CONSTANT("OPENSSL_ALGO_MD2", OPENSSL_ALGO_MD2, CONST_CS|CONST_PERSISTENT);
#endif
	REGISTER_LONG_CONSTANT("OPENSSL_ALGO_DSS1", OPENSSL_ALGO_DSS1, CONST_CS|CONST_PERSISTENT);
#if OPENSSL_VERSION_NUMBER >= 0x0090708fL
	REGISTER_LONG_CONSTANT("OPENSSL_ALGO_SHA224", OPENSSL_ALGO_SHA224, CONST_CS|CONST_PERSISTENT);
	REGISTER_LONG_CONSTANT("OPENSSL_ALGO_SHA256", OPENSSL_ALGO_SHA256, CONST_CS|CONST_PERSISTENT);
	REGISTER_LONG_CONSTANT("OPENSSL_ALGO_SHA384", OPENSSL_ALGO_SHA384, CONST_CS|CONST_PERSISTENT);
	REGISTER_LONG_CONSTANT("OPENSSL_ALGO_SHA512", OPENSSL_ALGO_SHA512, CONST_CS|CONST_PERSISTENT);
	REGISTER_LONG_CONSTANT("OPENSSL_ALGO_RMD160", OPENSSL_ALGO_RMD160, CONST_CS|CONST_PERSISTENT);
#endif

	/* Ciphers */
#ifndef OPENSSL_NO_RC2
	REGISTER_LONG_CONSTANT("OPENSSL_CIPHER_RC2_40", PHP_OPENSSL_CIPHER_RC2_40, CONST_CS|CONST_PERSISTENT);
	REGISTER_LONG_CONSTANT("OPENSSL_CIPHER_RC2_128", PHP_OPENSSL_CIPHER_RC2_128, CONST_CS|CONST_PERSISTENT);
	REGISTER_LONG_CONSTANT("OPENSSL_CIPHER_RC2_64", PHP_OPENSSL_CIPHER_RC2_64, CONST_CS|CONST_PERSISTENT);
#endif
#ifndef OPENSSL_NO_DES
	REGISTER_LONG_CONSTANT("OPENSSL_CIPHER_DES", PHP_OPENSSL_CIPHER_DES, CONST_CS|CONST_PERSISTENT);
	REGISTER_LONG_CONSTANT("OPENSSL_CIPHER_3DES", PHP_OPENSSL_CIPHER_3DES, CONST_CS|CONST_PERSISTENT);
#endif
#ifndef OPENSSL_NO_AES
	REGISTER_LONG_CONSTANT("OPENSSL_CIPHER_AES_128_CBC", PHP_OPENSSL_CIPHER_AES_128_CBC, CONST_CS|CONST_PERSISTENT);
	REGISTER_LONG_CONSTANT("OPENSSL_CIPHER_AES_192_CBC", PHP_OPENSSL_CIPHER_AES_192_CBC, CONST_CS|CONST_PERSISTENT);
	REGISTER_LONG_CONSTANT("OPENSSL_CIPHER_AES_256_CBC", PHP_OPENSSL_CIPHER_AES_256_CBC, CONST_CS|CONST_PERSISTENT);
#endif
 
	REGISTER_LONG_CONSTANT("OPENSSL_RAW_DATA", OPENSSL_RAW_DATA, CONST_CS|CONST_PERSISTENT);
	REGISTER_LONG_CONSTANT("OPENSSL_ZERO_PADDING", OPENSSL_ZERO_PADDING, CONST_CS|CONST_PERSISTENT);
#endif

	return SUCCESS;
}
/* }}} */

/* {{{ PHP_MINFO_FUNCTION
 */
PHP_MINFO_FUNCTION(openssl_incr)
{
	php_info_print_table_start();
	php_info_print_table_row(2, "OpenSSL-incremental support", "enabled");
	php_info_print_table_end();
}
/* }}} */

#ifndef HAVE_OPENSSL_EXT
/* {{{ PHP_MSHUTDOWN_FUNCTION
 */
PHP_MSHUTDOWN_FUNCTION(openssl_incr)
{
	EVP_cleanup();
	return SUCCESS;
}
/* }}} */
#endif



/* {{{ proto resource openssl_digest_init(string method)
   Initialises digest hash calculation for given method, returns a hashing context to be used with openssl_digest_update and openssl_digest_final */
PHP_FUNCTION(openssl_digest_init)
{
	char *method;
	php_strlen_t method_len;
	const EVP_MD *mdtype;
	php_openssl_digest_ctx* ctx;

	if (zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "s", &method, &method_len) == FAILURE) {
		return;
	}
	mdtype = EVP_get_digestbyname(method);
	if (!mdtype) {
		php_error_docref(NULL TSRMLS_CC, E_WARNING, "Unknown signature algorithm");
		RETURN_NULL();
	}

	ctx = (php_openssl_digest_ctx*) emalloc(sizeof(php_openssl_digest_ctx));
	ctx->siglen = EVP_MD_size(mdtype);

#if OPENSSL_VERSION_NUMBER >= 0x10100000L
	ctx->md_ctx = EVP_MD_CTX_new();
#endif
	EVP_DigestInit(_OPENSSL_CTX_REF(ctx->md_ctx), mdtype);
	ctx->complete = 0;
	
	PHP_RETURN_RESOURCE(ctx, le_digest);
}
/* }}} */
/* {{{ proto bool openssl_digest_update(resource ctx, string data)
   Updates digest hash context with given data, returns true */
PHP_FUNCTION(openssl_digest_update)
{
	zval* zv;
	char *data;
	php_strlen_t data_len;
	php_openssl_digest_ctx* ctx;

	if (zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "rs", &zv, &data, &data_len) == FAILURE) {
		return;
	}
	PHP_ASSIGN_RESOURCE(ctx, php_openssl_digest_ctx*, zv, PHP_OPENSSL_CTX_DIGEST_NAME, le_digest);
	if (!ctx) RETURN_FALSE;
	if (ctx->complete) {
		php_error_docref(NULL TSRMLS_CC, E_WARNING, "Resource closed");
		RETURN_FALSE;
	}
	EVP_DigestUpdate(_OPENSSL_CTX_REF(ctx->md_ctx), (unsigned char *)data, data_len);
	RETVAL_TRUE;
}
/* }}} */
/* {{{ proto string openssl_digest_final(resource ctx[, bool raw_output=false])
   Returns digest hash value for given hashing context, as raw or binhex encoded string */
PHP_FUNCTION(openssl_digest_final)
{
	zend_bool raw_output = 0;
	unsigned char *sigbuf;
	zval* zv;
	php_openssl_digest_ctx* ctx;
	
	if (zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "r|b", &zv, &raw_output) == FAILURE) {
		return;
	}
	PHP_ASSIGN_RESOURCE(ctx, php_openssl_digest_ctx*, zv, PHP_OPENSSL_CTX_DIGEST_NAME, le_digest);
	if (!ctx) RETURN_FALSE;
	if (ctx->complete) {
		php_error_docref(NULL TSRMLS_CC, E_WARNING, "Resource closed");
		RETURN_FALSE;
	}
	
	sigbuf = emalloc(ctx->siglen + 1);
	ctx->complete = 1;
	
	if (EVP_DigestFinal (_OPENSSL_CTX_REF(ctx->md_ctx), (unsigned char *)sigbuf, (unsigned int *)&(ctx->siglen))) {
		if (raw_output) {
			sigbuf[ctx->siglen] = '\0';
			PHP_RETURN_STRINGL((char *)sigbuf, ctx->siglen, 0);
		} else {
			int digest_str_len = ctx->siglen * 2;
			char *digest_str = emalloc(digest_str_len + 1);

			make_digest_ex(digest_str, sigbuf, ctx->siglen);
			efree(sigbuf);
			PHP_RETURN_STRINGL(digest_str, digest_str_len, 0);
		}
	} else {
		efree(sigbuf);
		RETVAL_FALSE;
	}
}
/* }}} */

static void php_openssl_copy_iv(char *piv, int piv_len, int iv_required_len, char *out_iv TSRMLS_DC)
{
	/* Best case scenario, user behaved */
	if (piv_len == iv_required_len) {
		memcpy(out_iv, piv, piv_len);
	}
	else if (piv_len <= 0) {
		memset(out_iv, 0, iv_required_len);
	}
	else if (piv_len < iv_required_len) {
		php_error_docref(NULL TSRMLS_CC, E_WARNING, "IV passed is only %d bytes long, cipher expects an IV of precisely %d bytes, padding with \\0", piv_len, iv_required_len);
		memcpy(out_iv, piv, piv_len);
		memset(out_iv + piv_len, 0, iv_required_len - piv_len);
	}
	else {
		php_error_docref(NULL TSRMLS_CC, E_WARNING, "IV passed is %d bytes long which is longer than the %d expected by selected cipher, truncating", piv_len, iv_required_len);
		memcpy(out_iv, piv, iv_required_len);
	}
}

/* {{{ proto resource openssl_encrypt_init(string method, string password [, long options=0 [, string $iv='']])
   Creates and returns a encryption context for given method and key */
PHP_FUNCTION(openssl_encrypt_init)
{
	php_long_t options = 0;
	char *method, *password, *iv = "";
	php_strlen_t method_len, password_len, iv_len = 0, max_iv_len;
	const EVP_CIPHER *cipher_type;
	int keylen;
	php_openssl_encdec_ctx* ctx;

	if (zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "ss|ls", &method, &method_len, &password, &password_len, &options, &iv, &iv_len) == FAILURE) {
		return;
	}
	cipher_type = EVP_get_cipherbyname(method);
	if (!cipher_type) {
		php_error_docref(NULL TSRMLS_CC, E_WARNING, "Unknown cipher algorithm");
		RETURN_NULL();
	}
	
	ctx = (php_openssl_encdec_ctx*)emalloc(sizeof(php_openssl_encdec_ctx));

	keylen = EVP_CIPHER_key_length(cipher_type);
	if(keylen > password_len) {
		ctx->key = emalloc(keylen);
		memset(ctx->key + password_len, 0, keylen - password_len);
	} else {
		ctx->key = emalloc(password_len);
	}
	memcpy(ctx->key, password, password_len);

	max_iv_len = EVP_CIPHER_iv_length(cipher_type);
	if (iv_len <= 0 && max_iv_len > 0) {
		php_error_docref(NULL TSRMLS_CC, E_WARNING, "Using an empty Initialization Vector (iv) is potentially insecure and not recommended");
	}
	ctx->iv = emalloc(max_iv_len);
	php_openssl_copy_iv(iv, iv_len, max_iv_len, ctx->iv TSRMLS_CC);

#if OPENSSL_VERSION_NUMBER >= 0x10100000L
	ctx->cipher_ctx = EVP_CIPHER_CTX_new();
#endif
	EVP_EncryptInit(_OPENSSL_CTX_REF(ctx->cipher_ctx), cipher_type, NULL, NULL);
	if (password_len > keylen) {
		EVP_CIPHER_CTX_set_key_length(_OPENSSL_CTX_REF(ctx->cipher_ctx), password_len);
	}
	EVP_EncryptInit_ex(_OPENSSL_CTX_REF(ctx->cipher_ctx), NULL, NULL, ctx->key, (unsigned char *)ctx->iv);
	if (options & OPENSSL_ZERO_PADDING) {
		EVP_CIPHER_CTX_set_padding(_OPENSSL_CTX_REF(ctx->cipher_ctx), 0);
	}
	ctx->block_size = EVP_CIPHER_block_size(cipher_type);
	ctx->complete = 0;
	
	PHP_RETURN_RESOURCE(ctx, le_encrypt);
}
/* }}} */
/* {{{ proto string openssl_encrypt_update(resource ctx, string data)
   Encrypts given data using given encryption context, returns raw string */
PHP_FUNCTION(openssl_encrypt_update)
{
	zval* zv;
	char *data;
	php_strlen_t data_len;
	int outlen;
	unsigned char *outbuf;
	php_openssl_encdec_ctx* ctx;

	if (zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "rs", &zv, &data, &data_len) == FAILURE) {
		return;
	}
	PHP_ASSIGN_RESOURCE(ctx, php_openssl_encdec_ctx*, zv, PHP_OPENSSL_CTX_ENCRYPT_NAME, le_encrypt);
	if (!ctx) RETURN_FALSE;
	if (ctx->complete) {
		php_error_docref(NULL TSRMLS_CC, E_WARNING, "Resource closed");
		RETURN_FALSE;
	}
	
	if(data_len < 1) {
		PHP_RETURN_STRINGL("", 0, 1);
	}

	outlen = data_len + ctx->block_size;
	outbuf = emalloc(outlen + 1);

	EVP_EncryptUpdate(_OPENSSL_CTX_REF(ctx->cipher_ctx), outbuf, &outlen, (unsigned char *)data, data_len);
	outbuf[outlen] = '\0';
	PHP_RETURN_STRINGL((char *)outbuf, outlen, 0);
}
/* }}} */
/* {{{ proto string openssl_encrypt_final(resource ctx)
   Returns any remaining data from encrypting context, and cleans everything up */
PHP_FUNCTION(openssl_encrypt_final)
{
	zval* zv;
	int outlen;
	unsigned char *outbuf;
	php_openssl_encdec_ctx* ctx;

	if (zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "r", &zv) == FAILURE) {
		return;
	}
	PHP_ASSIGN_RESOURCE(ctx, php_openssl_encdec_ctx*, zv, PHP_OPENSSL_CTX_ENCRYPT_NAME, le_encrypt);
	if (!ctx) RETURN_FALSE;
	if (ctx->complete) {
		php_error_docref(NULL TSRMLS_CC, E_WARNING, "Resource closed");
		RETURN_FALSE;
	}

	outlen = ctx->block_size;
	outbuf = emalloc(outlen + 1);
	
	ctx->complete = 1;
	if (EVP_EncryptFinal_ex(_OPENSSL_CTX_REF(ctx->cipher_ctx), outbuf, &outlen)) {
		outbuf[outlen] = '\0';
		PHP_RETURN_STRINGL((char *)outbuf, outlen, 0);
	} else {
		efree(outbuf);
		RETVAL_FALSE;
	}
	efree(ctx->key);
	ctx->key = NULL;
	efree(ctx->iv);
	ctx->iv = NULL;
#if OPENSSL_VERSION_NUMBER >= 0x10100000L
	EVP_CIPHER_CTX_free(ctx->cipher_ctx);
#else
	EVP_CIPHER_CTX_cleanup(_OPENSSL_CTX_REF(ctx->cipher_ctx));
#endif
}
/* }}} */

/* {{{ proto resource openssl_decrypt_init(string method, string password [, long options=0 [, string $iv = '']])
   Creates and returns a decryption context for given method and key */
PHP_FUNCTION(openssl_decrypt_init)
{
	php_long_t options = 0;
	char *method, *password, *iv = "";
	php_strlen_t method_len, password_len, iv_len = 0, max_iv_len;
	const EVP_CIPHER *cipher_type;
	int keylen;
	php_openssl_encdec_ctx* ctx;

	if (zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "ss|ls", &method, &method_len, &password, &password_len, &options, &iv, &iv_len) == FAILURE) {
		return;
	}

	cipher_type = EVP_get_cipherbyname(method);
	if (!cipher_type) {
		php_error_docref(NULL TSRMLS_CC, E_WARNING, "Unknown cipher algorithm");
		RETURN_NULL();
	}
	
	ctx = (php_openssl_encdec_ctx*)emalloc(sizeof(php_openssl_encdec_ctx));

	keylen = EVP_CIPHER_key_length(cipher_type);
	if(keylen > password_len) {
		ctx->key = emalloc(keylen);
		memset(ctx->key + password_len, 0, keylen - password_len);
	} else {
		ctx->key = emalloc(password_len);
	}
	memcpy(ctx->key, password, password_len);

	max_iv_len = EVP_CIPHER_iv_length(cipher_type);
	ctx->iv = emalloc(max_iv_len);
	php_openssl_copy_iv(iv, iv_len, max_iv_len, ctx->iv TSRMLS_CC);

#if OPENSSL_VERSION_NUMBER >= 0x10100000L
	ctx->cipher_ctx = EVP_CIPHER_CTX_new();
#endif
	EVP_DecryptInit(_OPENSSL_CTX_REF(ctx->cipher_ctx), cipher_type, NULL, NULL);
	if (password_len > keylen) {
		EVP_CIPHER_CTX_set_key_length(_OPENSSL_CTX_REF(ctx->cipher_ctx), password_len);
	}
	EVP_DecryptInit_ex(_OPENSSL_CTX_REF(ctx->cipher_ctx), NULL, NULL, ctx->key, (unsigned char *)ctx->iv);
	if (options & OPENSSL_ZERO_PADDING) {
		EVP_CIPHER_CTX_set_padding(_OPENSSL_CTX_REF(ctx->cipher_ctx), 0);
	}
	ctx->block_size = EVP_CIPHER_block_size(cipher_type);
	ctx->complete = 0;
	
	PHP_RETURN_RESOURCE(ctx, le_decrypt);
}
/* }}} */
/* {{{ proto string openssl_decrypt_update(resource ctx, string data)
   Decrypts and returns given raw data using given decryption context */
PHP_FUNCTION(openssl_decrypt_update)
{
	zval* zv;
	char *data;
	php_strlen_t data_len;
	int outlen;
	unsigned char *outbuf;
	php_openssl_encdec_ctx* ctx;

	if (zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "rs", &zv, &data, &data_len) == FAILURE) {
		return;
	}
	PHP_ASSIGN_RESOURCE(ctx, php_openssl_encdec_ctx*, zv, PHP_OPENSSL_CTX_DECRYPT_NAME, le_decrypt);
	if (!ctx) RETURN_FALSE;
	if (ctx->complete) {
		php_error_docref(NULL TSRMLS_CC, E_WARNING, "Resource closed");
		RETURN_FALSE;
	}
	
	if(data_len < 1) {
		PHP_RETURN_STRINGL("", 0, 1);
	}

	outlen = data_len + ctx->block_size;
	outbuf = emalloc(outlen + 1);

	EVP_DecryptUpdate(_OPENSSL_CTX_REF(ctx->cipher_ctx), outbuf, &outlen, (unsigned char *)data, data_len);
	outbuf[outlen] = '\0';
	PHP_RETURN_STRINGL((char *)outbuf, outlen, 0);
}
/* }}} */
/* {{{ proto string openssl_decrypt_final(resource ctx)
   Returns any remaining data from decrypting context, and cleans everything up */
PHP_FUNCTION(openssl_decrypt_final)
{
	zval* zv;
	int outlen;
	unsigned char *outbuf;
	php_openssl_encdec_ctx* ctx;

	if (zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "r", &zv) == FAILURE) {
		return;
	}
	PHP_ASSIGN_RESOURCE(ctx, php_openssl_encdec_ctx*, zv, PHP_OPENSSL_CTX_DECRYPT_NAME, le_decrypt);
	if (!ctx) RETURN_FALSE;
	if (ctx->complete) {
		php_error_docref(NULL TSRMLS_CC, E_WARNING, "Resource closed");
		RETURN_FALSE;
	}

	outlen = ctx->block_size;
	outbuf = emalloc(outlen + 1);

	ctx->complete = 1;
	if (EVP_DecryptFinal_ex(_OPENSSL_CTX_REF(ctx->cipher_ctx), (unsigned char *)outbuf, &outlen)) {
		outbuf[outlen] = '\0';
		PHP_RETURN_STRINGL((char *)outbuf, outlen, 0);
	} else {
		efree(outbuf);
		RETVAL_FALSE;
	}
	efree(ctx->key);
	ctx->key = NULL;
	efree(ctx->iv);
	ctx->iv = NULL;
	
#if OPENSSL_VERSION_NUMBER >= 0x10100000L
	EVP_CIPHER_CTX_free(ctx->cipher_ctx);
#else
	EVP_CIPHER_CTX_cleanup(_OPENSSL_CTX_REF(ctx->cipher_ctx));
#endif
}
/* }}} */

/*
 * Local variables:
 * tab-width: 8
 * c-basic-offset: 8
 * End:
 * vim600: sw=4 ts=4 fdm=marker
 * vim<600: sw=4 ts=4
 */

