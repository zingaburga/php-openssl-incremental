
PHP_ARG_WITH(openssl, for OpenSSL support,
[  --with-openssl[=DIR]      Include OpenSSL support (requires OpenSSL >= 0.9.6)])

if test "$PHP_OPENSSL" != "no"; then
  PHP_NEW_EXTENSION(openssl_incr, openssl.c, $ext_shared)
  PHP_SUBST(OPENSSL_SHARED_LIBADD)

  AC_CHECK_LIB(crypto, DSA_get_default_method, AC_DEFINE(HAVE_DSA_DEFAULT_METHOD, 1, [OpenSSL 0.9.7 or later]))
  AC_DEFINE(HAVE_OPENSSL_EXT,1,[ ])
  
  PHP_SETUP_OPENSSL(OPENSSL_SHARED_LIBADD, 
  [
    AC_DEFINE(HAVE_OPENSSL_INCR_EXT,1,[ ])
  ], [
    AC_MSG_ERROR([OpenSSL check failed. Please check config.log for more information.])
  ])
fi
