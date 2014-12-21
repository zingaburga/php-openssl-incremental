
#ifndef PHP_OPENSSL_INCR_H
#define PHP_OPENSSL_INCR_H

#ifdef HAVE_OPENSSL_INCR_EXT
extern zend_module_entry openssl_incr_module_entry;
#define phpext_openssl_incr_ptr &openssl_incr_module_entry

#ifndef OPENSSL_RAW_DATA
#define OPENSSL_RAW_DATA 1
#define OPENSSL_ZERO_PADDING 2
#endif

PHP_MINIT_FUNCTION(openssl_incr);
#ifndef HAVE_OPENSSL_EXT
PHP_MSHUTDOWN_FUNCTION(openssl_incr);
#endif
PHP_MINFO_FUNCTION(openssl_incr);

#else
#define phpext_openssl_incr_ptr NULL
#endif

#endif

/*
 * Local variables:
 * tab-width: 4
 * c-basic-offset: 4
 * End:
 */
