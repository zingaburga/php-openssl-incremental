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

// test size functions
var_dump(openssl_digest_size('sha1'), openssl_digest_block_size('md5'));
var_dump(openssl_digest_size(''), openssl_digest_block_size(''));

// test context copying
$a = openssl_digest_init('md5');
openssl_digest_update($a, 'the fox ');
$b = openssl_digest_copy($a);
openssl_digest_update($a, 'jumped');
openssl_digest_update($b, 'escaped');
var_dump(openssl_digest_final($a), openssl_digest_final($b));

var_dump(openssl_digest_copy($a)); // closed context
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
int(20)
int(64)

Warning: openssl_digest_size(): Unknown signature algorithm in %s on line %d

Warning: openssl_digest_block_size(): Unknown signature algorithm in %s on line %d
NULL
NULL
string(32) "c794342cde676abfeaff27509db14f71"
string(32) "e68f5993afb5cb6a225f1c97b79a3c2a"

Warning: openssl_digest_copy(): Resource closed in %s on line %d
bool(false)
