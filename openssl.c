
#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "php.h"
#include "php_openssl.h"

/* PHP Includes */
#include "ext/standard/md5.h"
#include "ext/standard/base64.h"

/* OpenSSL includes */
#include <openssl/evp.h>
#include <openssl/ssl.h>

/*
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
*/

typedef struct {
	EVP_MD_CTX md_ctx;
	int complete;
	int siglen;
} php_openssl_digest_ctx;

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
	PHP_MSHUTDOWN(openssl_incr),
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
#define PHP_OPENSSL_CTX_ENCRYPT_NAME "OpenSSL digest context"
#define PHP_OPENSSL_CTX_DECRYPT_NAME "OpenSSL digest context"
static int le_digest;
static int le_encrypt;
static int le_decrypt;

/* {{{ resource destructors */
static void php_digest_free(zend_rsrc_list_entry *rsrc TSRMLS_DC)
{
	php_openssl_digest_ctx* ctx = (php_openssl_digest_ctx*)rsrc->ptr;
	if(!ctx->complete) EVP_MD_CTX_destroy(&ctx->md_ctx);
	efree(ctx);
}

/* }}} */


/* {{{ PHP_MINIT_FUNCTION
 */
PHP_MINIT_FUNCTION(openssl_incr)
{
	le_digest = zend_register_list_destructors_ex(php_digest_free, NULL, PHP_OPENSSL_CTX_DIGEST_NAME, module_number);

	SSL_library_init();
	OpenSSL_add_all_ciphers();
	OpenSSL_add_all_digests();
	OpenSSL_add_all_algorithms();

	//SSL_load_error_strings();
	
	/* signature algorithm constants; assume already defined by OpenSSL extension */
	/*
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
*/
	/* Ciphers */
	/*
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
*/

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

/* {{{ PHP_MSHUTDOWN_FUNCTION
 */
PHP_MSHUTDOWN_FUNCTION(openssl_incr)
{
	EVP_cleanup();
	return SUCCESS;
}
/* }}} */



/* {{{ proto resource openssl_digest_init(string method [, bool raw_output=false])
   Computes digest hash value for given data using given method, returns raw or binhex encoded string */
PHP_FUNCTION(openssl_digest_init)
{
	char *method;
	int method_len;
	const EVP_MD *mdtype;
	php_openssl_digest_ctx* ctx;

	if (zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "s", &method, &method_len) == FAILURE) {
		return;
	}
	mdtype = EVP_get_digestbyname(method);
	if (!mdtype) {
		php_error_docref(NULL TSRMLS_CC, E_WARNING, "Unknown signature algorithm");
		RETURN_FALSE;
	}

	ctx = (php_openssl_digest_ctx*) emalloc(sizeof(php_openssl_digest_ctx));
	ctx->siglen = EVP_MD_size(mdtype);

	EVP_DigestInit(&(ctx->md_ctx), mdtype);
	ctx->complete = FALSE;
	
	ZEND_REGISTER_RESOURCE(return_value, ctx, le_digest);
}
/* }}} */
/* {{{ proto bool openssl_digest_update(resource ctx, string data)
   Computes digest hash value for given data using given method, returns raw or binhex encoded string */
PHP_FUNCTION(openssl_digest_update)
{
	zval* zv
	char *data;
	int data_len;
	php_openssl_digest_ctx* ctx;

	if (zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "rs", &zv, &data, &data_len) == FAILURE) {
		return;
	}
	ZEND_FETCH_RESOURCE(ctx, php_openssl_digest_ctx*, &zv, -1, PHP_OPENSSL_CTX_DIGEST_NAME, le_digest);
	EVP_DigestUpdate(&(ctx->md_ctx), (unsigned char *)data, data_len);
	RETVAL_TRUE;
}
/* }}} */
/* {{{ proto string openssl_digest_final(resource ctx[, bool raw_output=false])
   Computes digest hash value for given data using given method, returns raw or binhex encoded string */
PHP_FUNCTION(openssl_digest_final)
{
	zend_bool raw_output = 0;
	unsigned char *sigbuf;
	zval* zv
	php_openssl_digest_ctx* ctx;
	

	if (zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "r|b", &zv, &raw_output) == FAILURE) {
		return;
	}
	ZEND_FETCH_RESOURCE(ctx, php_openssl_digest_ctx*, &zv, -1, PHP_OPENSSL_CTX_DIGEST_NAME, le_digest);
	
	sigbuf = emalloc(ctx->siglen + 1);
	ctx->complete = TRUE;
	
	if (EVP_DigestFinal (&(ctx->md_ctx), (unsigned char *)sigbuf, (unsigned int *)&(ctx->siglen))) {
		if (raw_output) {
			sigbuf[ctx->siglen] = '\0';
			RETVAL_STRINGL((char *)sigbuf, siglen, 0);
		} else {
			int digest_str_len = ctx->siglen * 2;
			char *digest_str = emalloc(digest_str_len + 1);

			make_digest_ex(digest_str, sigbuf, ctx->siglen);
			efree(sigbuf);
			RETVAL_STRINGL(digest_str, digest_str_len, 0);
		}
	} else {
		efree(sigbuf);
		RETVAL_FALSE;
	}
}
/* }}} */

static zend_bool php_openssl_validate_iv(char **piv, int *piv_len, int iv_required_len TSRMLS_DC)
{
	char *iv_new;

	/* Best case scenario, user behaved */
	if (*piv_len == iv_required_len) {
		return 0;
	}

	iv_new = ecalloc(1, iv_required_len + 1);

	if (*piv_len <= 0) {
		/* BC behavior */
		*piv_len = iv_required_len;
		*piv     = iv_new;
		return 1;
	}

	if (*piv_len < iv_required_len) {
		php_error_docref(NULL TSRMLS_CC, E_WARNING, "IV passed is only %d bytes long, cipher expects an IV of precisely %d bytes, padding with \\0", *piv_len, iv_required_len);
		memcpy(iv_new, *piv, *piv_len);
		*piv_len = iv_required_len;
		*piv     = iv_new;
		return 1;
	}

	php_error_docref(NULL TSRMLS_CC, E_WARNING, "IV passed is %d bytes long which is longer than the %d expected by selected cipher, truncating", *piv_len, iv_required_len);
	memcpy(iv_new, *piv, iv_required_len);
	*piv_len = iv_required_len;
	*piv     = iv_new;
	return 1;

}

/* {{{ proto string openssl_encrypt(string data, string method, string password [, long options=0 [, string $iv='']])
   Encrypts given data with given method and key, returns raw or base64 encoded string */
PHP_FUNCTION(openssl_encrypt)
{
	long options = 0;
	char *data, *method, *password, *iv = "";
	int data_len, method_len, password_len, iv_len = 0, max_iv_len;
	const EVP_CIPHER *cipher_type;
	EVP_CIPHER_CTX cipher_ctx;
	int i=0, outlen, keylen;
	unsigned char *outbuf, *key;
	zend_bool free_iv;

	if (zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "sss|ls", &data, &data_len, &method, &method_len, &password, &password_len, &options, &iv, &iv_len) == FAILURE) {
		return;
	}
	cipher_type = EVP_get_cipherbyname(method);
	if (!cipher_type) {
		php_error_docref(NULL TSRMLS_CC, E_WARNING, "Unknown cipher algorithm");
		RETURN_FALSE;
	}

	keylen = EVP_CIPHER_key_length(cipher_type);
	if (keylen > password_len) {
		key = emalloc(keylen);
		memset(key, 0, keylen);
		memcpy(key, password, password_len);
	} else {
		key = (unsigned char*)password;
	}

	max_iv_len = EVP_CIPHER_iv_length(cipher_type);
	if (iv_len <= 0 && max_iv_len > 0) {
		php_error_docref(NULL TSRMLS_CC, E_WARNING, "Using an empty Initialization Vector (iv) is potentially insecure and not recommended");
	}
	free_iv = php_openssl_validate_iv(&iv, &iv_len, max_iv_len TSRMLS_CC);

	outlen = data_len + EVP_CIPHER_block_size(cipher_type);
	outbuf = emalloc(outlen + 1);

	EVP_EncryptInit(&cipher_ctx, cipher_type, NULL, NULL);
	if (password_len > keylen) {
		EVP_CIPHER_CTX_set_key_length(&cipher_ctx, password_len);
	}
	EVP_EncryptInit_ex(&cipher_ctx, NULL, NULL, key, (unsigned char *)iv);
	if (options & OPENSSL_ZERO_PADDING) {
		EVP_CIPHER_CTX_set_padding(&cipher_ctx, 0);
	}
	if (data_len > 0) {
		EVP_EncryptUpdate(&cipher_ctx, outbuf, &i, (unsigned char *)data, data_len);
	}
	outlen = i;
	if (EVP_EncryptFinal(&cipher_ctx, (unsigned char *)outbuf + i, &i)) {
		outlen += i;
		if (options & OPENSSL_RAW_DATA) {
			outbuf[outlen] = '\0';
			RETVAL_STRINGL((char *)outbuf, outlen, 0);
		} else {
			int base64_str_len;
			char *base64_str;

			base64_str = (char*)php_base64_encode(outbuf, outlen, &base64_str_len);
			efree(outbuf);
			RETVAL_STRINGL(base64_str, base64_str_len, 0);
		}
	} else {
		efree(outbuf);
		RETVAL_FALSE;
	}
	if (key != (unsigned char*)password) {
		efree(key);
	}
	if (free_iv) {
		efree(iv);
	}
	EVP_CIPHER_CTX_cleanup(&cipher_ctx);
}
/* }}} */

/* {{{ proto string openssl_decrypt(string data, string method, string password [, long options=0 [, string $iv = '']])
   Takes raw or base64 encoded string and dectupt it using given method and key */
PHP_FUNCTION(openssl_decrypt)
{
	long options = 0;
	char *data, *method, *password, *iv = "";
	int data_len, method_len, password_len, iv_len = 0;
	const EVP_CIPHER *cipher_type;
	EVP_CIPHER_CTX cipher_ctx;
	int i, outlen, keylen;
	unsigned char *outbuf, *key;
	int base64_str_len;
	char *base64_str = NULL;
	zend_bool free_iv;

	if (zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "sss|ls", &data, &data_len, &method, &method_len, &password, &password_len, &options, &iv, &iv_len) == FAILURE) {
		return;
	}

	if (!method_len) {
		php_error_docref(NULL TSRMLS_CC, E_WARNING, "Unknown cipher algorithm");
		RETURN_FALSE;
	}

	cipher_type = EVP_get_cipherbyname(method);
	if (!cipher_type) {
		php_error_docref(NULL TSRMLS_CC, E_WARNING, "Unknown cipher algorithm");
		RETURN_FALSE;
	}

	if (!(options & OPENSSL_RAW_DATA)) {
		base64_str = (char*)php_base64_decode((unsigned char*)data, data_len, &base64_str_len);
		if (!base64_str) {
			php_error_docref(NULL TSRMLS_CC, E_WARNING, "Failed to base64 decode the input");
			RETURN_FALSE;
		}
		data_len = base64_str_len;
		data = base64_str;
	}

	keylen = EVP_CIPHER_key_length(cipher_type);
	if (keylen > password_len) {
		key = emalloc(keylen);
		memset(key, 0, keylen);
		memcpy(key, password, password_len);
	} else {
		key = (unsigned char*)password;
	}

	free_iv = php_openssl_validate_iv(&iv, &iv_len, EVP_CIPHER_iv_length(cipher_type) TSRMLS_CC);

	outlen = data_len + EVP_CIPHER_block_size(cipher_type);
	outbuf = emalloc(outlen + 1);

	EVP_DecryptInit(&cipher_ctx, cipher_type, NULL, NULL);
	if (password_len > keylen) {
		EVP_CIPHER_CTX_set_key_length(&cipher_ctx, password_len);
	}
	EVP_DecryptInit_ex(&cipher_ctx, NULL, NULL, key, (unsigned char *)iv);
	if (options & OPENSSL_ZERO_PADDING) {
		EVP_CIPHER_CTX_set_padding(&cipher_ctx, 0);
	}
	EVP_DecryptUpdate(&cipher_ctx, outbuf, &i, (unsigned char *)data, data_len);
	outlen = i;
	if (EVP_DecryptFinal(&cipher_ctx, (unsigned char *)outbuf + i, &i)) {
		outlen += i;
		outbuf[outlen] = '\0';
		RETVAL_STRINGL((char *)outbuf, outlen, 0);
	} else {
		efree(outbuf);
		RETVAL_FALSE;
	}
	if (key != (unsigned char*)password) {
		efree(key);
	}
	if (free_iv) {
		efree(iv);
	}
	if (base64_str) {
		efree(base64_str);
	}
 	EVP_CIPHER_CTX_cleanup(&cipher_ctx);
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

