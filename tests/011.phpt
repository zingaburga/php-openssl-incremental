--TEST--
openssl_encrypt*() and openssl_decrypt*() tests
--SKIPIF--
<?php if (!extension_loaded("openssl") || !extension_loaded("openssl_incr")) print "skip"; ?>
--FILE--
<?php
$data = "openssl_encrypt() and openssl_decrypt() tests";
$method = "AES-128-CBC";
$password = md5("openssl", true);
$iv    = md5('some fixed IV', true);

$h = openssl_encrypt_init($method, $password, OPENSSL_RAW_DATA, $iv);
$encrypted = openssl_encrypt_update($h, $data).openssl_encrypt_final($h);
var_dump(base64_encode($encrypted));
$h = openssl_decrypt_init($method, $password, OPENSSL_RAW_DATA, $iv);
openssl_decrypt_update($h, ''); // test sending blank data
$output = openssl_decrypt_update($h, $encrypted).openssl_decrypt_final($h);
var_dump($output);
// if we want to manage our own padding
$h = openssl_encrypt_init($method, $password, OPENSSL_RAW_DATA|OPENSSL_ZERO_PADDING, $iv);
openssl_encrypt_update($h, ''); // test sending blank data
$encrypted = openssl_encrypt_update($h, $data)
            .openssl_encrypt_update($h, str_repeat(' ', 16 - (strlen($data) % 16)))
            .openssl_encrypt_final($h);
var_dump(base64_encode($encrypted));
$h = openssl_decrypt_init($method, $password, OPENSSL_RAW_DATA|OPENSSL_ZERO_PADDING, $iv);
$output = openssl_decrypt_update($h, $encrypted).openssl_decrypt_final($h);
var_dump(rtrim($output));


// test invalid method
var_dump(openssl_encrypt_init('invalid method', $password, 0, $iv));
var_dump(openssl_decrypt_init('invalid method', $password, 0, $iv));

// test blank update + raw output
$h = openssl_encrypt_init($method, $password, OPENSSL_RAW_DATA, $iv);
var_dump(openssl_encrypt_final($h) == openssl_encrypt('', $method, $password, OPENSSL_RAW_DATA, $iv));
$h = openssl_encrypt_init($method, $password, OPENSSL_RAW_DATA|OPENSSL_ZERO_PADDING, $iv);
var_dump(openssl_encrypt_final($h) == openssl_encrypt('', $method, $password, OPENSSL_RAW_DATA|OPENSSL_ZERO_PADDING, $iv));
$h = openssl_decrypt_init($method, $password, OPENSSL_RAW_DATA, $iv);
var_dump(openssl_decrypt_final($h) == openssl_decrypt('', $method, $password, OPENSSL_RAW_DATA, $iv));
$h = openssl_decrypt_init($method, $password, OPENSSL_RAW_DATA|OPENSSL_ZERO_PADDING, $iv);
var_dump(openssl_decrypt_final($h) == openssl_decrypt('', $method, $password, OPENSSL_RAW_DATA|OPENSSL_ZERO_PADDING, $iv));

// test reusing completed context or bad context
var_dump(openssl_decrypt_update($h, 'blah'));
var_dump(openssl_decrypt_final($h));
var_dump(openssl_encrypt_update($h, 'blah')); // invalid context
$h = openssl_encrypt_init($method, $password, OPENSSL_RAW_DATA, $iv);
openssl_encrypt_final($h);
var_dump(openssl_encrypt_update($h, 'blah'));
var_dump(openssl_encrypt_final($h));
var_dump(openssl_decrypt_update($h, 'blah')); // invalid context

function test_pwdiv($password, $iv) {
	global $method, $data;
	$h = openssl_encrypt_init($method, $password, OPENSSL_RAW_DATA, $iv);
	$encrypted = openssl_encrypt_update($h, $data).openssl_encrypt_final($h);
	var_dump($encrypted == @openssl_encrypt($data, $method, $password, OPENSSL_RAW_DATA, $iv));
	
	// note that we can't test with OPENSSL_ZERO_PADDING because OpenSSL throws an error if data is not aligned to the block size
	// hence, it's expected behaviour that openssl-incremental behaves differently to openssl in this case
	
	$h = openssl_decrypt_init($method, $password, OPENSSL_RAW_DATA, $iv);
	$output = openssl_decrypt_update($h, $encrypted).openssl_decrypt_final($h);
	var_dump($output);
}

// test weird passwords
// if short, NULL pad, if too long, truncate
test_pwdiv('', $iv);
test_pwdiv(substr($password, 0, 4), $iv);
test_pwdiv($password.$password, $iv);

// test bad IV
// empty = warning, too short = warning + padding, too long = warning + truncate
test_pwdiv($password, '');
test_pwdiv($password, substr($iv, 0, 4));
test_pwdiv($password, $iv.$iv);

// test info functions
var_dump(openssl_cipher_block_size('aes-256-cbc'), 
	openssl_cipher_key_length('aes-256-cbc'),
	openssl_cipher_mode('aes-256-cbc') == OPENSSL_CIPH_CBC_MODE
);
var_dump(openssl_cipher_block_size(''), openssl_cipher_key_length(''), openssl_cipher_mode(''));
?>
--EXPECTF--
string(64) "54CX4A94Jz2K0JSTnvnTXkEfzCeLK6yFVEFUn7wJPD2MoXddWQQd3RmLG0+5XEmg"
string(45) "openssl_encrypt() and openssl_decrypt() tests"
string(64) "54CX4A94Jz2K0JSTnvnTXkEfzCeLK6yFVEFUn7wJPD18DSyosasvDJXMNXN8E0mB"
string(45) "openssl_encrypt() and openssl_decrypt() tests"

Warning: openssl_encrypt_init(): Unknown cipher algorithm in %s on line %d
NULL

Warning: openssl_decrypt_init(): Unknown cipher algorithm in %s on line %d
NULL
bool(true)
bool(true)
bool(true)
bool(true)

Warning: openssl_decrypt_update(): Resource closed in %s on line %d
bool(false)

Warning: openssl_decrypt_final(): Resource closed in %s on line %d
bool(false)

Warning: openssl_encrypt_update(): supplied resource is not a valid OpenSSL encrypt context resource in %s on line %d
bool(false)

Warning: openssl_encrypt_update(): Resource closed in %s on line %d
bool(false)

Warning: openssl_encrypt_final(): Resource closed in %s on line %d
bool(false)

Warning: openssl_decrypt_update(): supplied resource is not a valid OpenSSL decrypt context resource in %s on line %d
bool(false)
bool(true)
string(45) "openssl_encrypt() and openssl_decrypt() tests"
bool(true)
string(45) "openssl_encrypt() and openssl_decrypt() tests"
bool(true)
string(45) "openssl_encrypt() and openssl_decrypt() tests"

Warning: openssl_encrypt_init(): Using an empty Initialization Vector (iv) is potentially insecure and not recommended in %s on line %d
bool(true)
string(45) "openssl_encrypt() and openssl_decrypt() tests"

Warning: openssl_encrypt_init(): IV passed is only 4 bytes long, cipher expects an IV of precisely 16 bytes, padding with \0 in %s on line %d
bool(true)

Warning: openssl_decrypt_init(): IV passed is only 4 bytes long, cipher expects an IV of precisely 16 bytes, padding with \0 in %s on line %d
string(45) "openssl_encrypt() and openssl_decrypt() tests"

Warning: openssl_encrypt_init(): IV passed is 32 bytes long which is longer than the 16 expected by selected cipher, truncating in %s on line %d
bool(true)

Warning: openssl_decrypt_init(): IV passed is 32 bytes long which is longer than the 16 expected by selected cipher, truncating in %s on line %d
string(45) "openssl_encrypt() and openssl_decrypt() tests"
int(16)
int(32)
bool(true)

Warning: openssl_cipher_block_size(): Unknown cipher algorithm in %s on line %d

Warning: openssl_cipher_key_length(): Unknown cipher algorithm in %s on line %d

Warning: openssl_cipher_mode(): Unknown cipher algorithm in %s on line %d
NULL
NULL
NULL
