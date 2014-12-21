--TEST--
openssl_digest*() basic test
--SKIPIF--
<?php if (!extension_loaded("openssl") || !extension_loaded("openssl_incr")) print "skip"; ?>
--FILE--
<?php
$data1 = "openssl_digest";
$data2 = "() basic test";
$method = "md5";
$method2 = "sha1";

// tests adopted from php-openssl
$h = openssl_digest_init($method);
openssl_digest_update($h, $data1);
openssl_digest_update($h, '');
openssl_digest_update($h, $data2);
var_dump(openssl_digest_final($h));
$h = openssl_digest_init($method2);
var_dump(openssl_digest_update($h, $data1.$data2));
var_dump(openssl_digest_final($h));

// test invalid method
var_dump(openssl_digest_init('invalid method'));

// test blank update + raw output
$h = openssl_digest_init($method2);
var_dump(bin2hex(openssl_digest_final($h, true)));

// test reusing completed context
var_dump(openssl_digest_update($h, 'blah'));
var_dump(openssl_digest_final($h));
?>
--EXPECTF--
string(32) "f0045b6c41d9ec835cb8948c7fec4955"
bool(true)
string(40) "aa6e750fef05c2414c18860ad31f2c35e79bf3dc"

Warning: openssl_digest_init(): Unknown signature algorithm in %s on line %d
NULL
string(40) "da39a3ee5e6b4b0d3255bfef95601890afd80709"

Warning: openssl_digest_update(): Resource closed in %s on line %d
bool(false)

Warning: openssl_digest_final(): Resource closed in %s on line %d
bool(false)
