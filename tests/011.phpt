--TEST--
openssl_encrypt*() and openssl_decrypt*() tests
--SKIPIF--
<?php if (!extension_loaded("openssl") || !extension_loaded("openssl_incr")) print "skip"; ?>
--FILE--
<?php
$data = "openssl_encrypt() and openssl_decrypt() tests";
$method = "AES-128-CBC";
$password = "openssl";

$ivlen = openssl_cipher_iv_length($method);
$iv    = '';
srand(time() + ((microtime(true) * 1000000) % 1000000));
while(strlen($iv) < $ivlen) $iv .= chr(rand(0,255));

$h = openssl_encrypt_init($method, $password, 0, $iv);
$encrypted = openssl_encrypt_update($h, $data).openssl_encrypt_final($h);
$h = openssl_decrypt_init($method, $password, 0, $iv);
$output = openssl_decrypt_update($h, $encrypted).openssl_decrypt_final($h);
var_dump($output);
// if we want to manage our own padding
$h = openssl_encrypt_init($method, $password, OPENSSL_RAW_DATA|OPENSSL_ZERO_PADDING, $iv);
$encrypted = openssl_encrypt_update($h, $data)
            .openssl_encrypt_update($h, str_repeat(' ', 16 - (strlen($data) % 16)))
            .openssl_encrypt_final($h);
$h = openssl_decrypt_init($method, $password, OPENSSL_RAW_DATA|OPENSSL_ZERO_PADDING, $iv);
$output = openssl_decrypt_update($h, $encrypted).openssl_decrypt_final($h);
var_dump(rtrim($output));
?>
--EXPECT--
string(45) "openssl_encrypt() and openssl_decrypt() tests"
string(45) "openssl_encrypt() and openssl_decrypt() tests"
