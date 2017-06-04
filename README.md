This PHP extension provides the ability to incrementally hash/encrypt/decrypt data using OpenSSL.  More specifically, it provides init/update/final variants of the `openssl_digest`, `openssl_encrypt` and `openssl_decrypt` PHP functions.

But the `hash` and `mcrypt` extensions already do this!
===
1. OpenSSL is usually a fair bit faster
2. OpenSSL can make use of hardware acceleration, which can make it even faster

So essentially, if speed isn't a concern, you don't need this extension.  But chances are that you do have some care, if you need incremental processing.

Motivation
===
Some (non scientific) speed demonstrations, without using this extension.  [This script](bench.php) was used on a few different CPUs, executing under PHP 5.5.  
(the "fingerprint" is only used to verify that the output of the functions are identical)

Intel Xeon X5650 [AES-NI support]

	sha1                          : fingerprint = b70c1887; speed = 142.583 MB/s
	hash (sha1)                   : fingerprint = b70c1887; speed = 189.041 MB/s
	openssl_digest (sha1)         : fingerprint = b70c1887; speed = 464.987 MB/s
	---
	hash (sha256)                 : fingerprint = 5e1c25a1; speed = 92.435 MB/s
	openssl_digest (sha256)       : fingerprint = 5e1c25a1; speed = 136.683 MB/s
	---
	md5                           : fingerprint = 63d0fc2b; speed = 442.284 MB/s
	hash (md5)                    : fingerprint = 63d0fc2b; speed = 437.663 MB/s
	openssl_digest (md5)          : fingerprint = 63d0fc2b; speed = 511.088 MB/s
	---
	mcrypt_encrypt (aes)          : fingerprint = 4bbb6b7d; speed = 40.412 MB/s
	openssl_encrypt (aes)         : fingerprint = 4bbb6b7d; speed = 546.724 MB/s

Via Nano U2250 ([patched OpenSSL](https://romanrm.net/openssl-padlock)) [Via Padlock (h/w accel SHA and AES)]

	sha1                          : fingerprint = b70c1887; speed = 101.699 MB/s
	hash (sha1)                   : fingerprint = b70c1887; speed = 108.982 MB/s
	openssl_digest (sha1)         : fingerprint = b70c1887; speed = 410.126 MB/s
	---
	hash (sha256)                 : fingerprint = 5e1c25a1; speed = 37.355 MB/s
	openssl_digest (sha256)       : fingerprint = 5e1c25a1; speed = 358.140 MB/s
	---
	md5                           : fingerprint = 63d0fc2b; speed = 225.396 MB/s
	hash (md5)                    : fingerprint = 63d0fc2b; speed = 214.926 MB/s
	openssl_digest (md5)          : fingerprint = 63d0fc2b; speed = 252.073 MB/s
	---
	mcrypt_encrypt (aes)          : fingerprint = 4bbb6b7d; speed = 17.772 MB/s
	openssl_encrypt (aes)         : fingerprint = 4bbb6b7d; speed = 324.253 MB/s

Intel Core i5 3570 (in VM without AES-NI) [no h/w acceleration]

	sha1                          : fingerprint = b70c1887; speed = 474.349 MB/s
	hash (sha1)                   : fingerprint = b70c1887; speed = 471.570 MB/s
	openssl_digest (sha1)         : fingerprint = b70c1887; speed = 803.955 MB/s
	---
	hash (sha256)                 : fingerprint = 5e1c25a1; speed = 185.468 MB/s
	openssl_digest (sha256)       : fingerprint = 5e1c25a1; speed = 296.122 MB/s
	---
	md5                           : fingerprint = 63d0fc2b; speed = 687.946 MB/s
	hash (md5)                    : fingerprint = 63d0fc2b; speed = 692.071 MB/s
	openssl_digest (md5)          : fingerprint = 63d0fc2b; speed = 750.116 MB/s
	---
	mcrypt_encrypt (aes)          : fingerprint = 4bbb6b7d; speed = 129.070 MB/s
	openssl_encrypt (aes)         : fingerprint = 4bbb6b7d; speed = 360.646 MB/s

Installation
===
_Note that this extension assumes that the PHP openssl extension is installed and loaded_

You'll need the PHP development libraries, as well as the OpenSSL dev files.  On Debian, you can do a `apt-get install php5-dev libssl-dev` to grab these.  And of course, you'll need something to compile with, so `apt-get install build-essential pkg-config` might be useful too.

Compile as shared library on Linux
---
Use the following commands in the directory where the files are:

	phpize
	./configure
	make
	make install

Now load the module in your php.ini, or use [dl](http://php.net/manual/en/function.dl.php)

Other platforms
---
No clue, do your own research

Functions
===
resource openssl_digest_init(string method)
---
Initialises digest hash calculation for given method, returns a hashing context to be used with `openssl_digest_update` and `openssl_digest_final`

See also [openssl_digest](http://php.net/manual/en/function.openssl-digest.php) [hash_init](http://php.net/manual/en/function.hash-init.php)

bool openssl_digest_update(resource ctx, string data)
---
Updates digest hash context with given data, returns true

See also [hash_update](http://php.net/manual/en/function.hash-update.php)

string openssl_digest_final(resource ctx [, bool raw_output=false])
---
Returns digest hash value for given hashing context, as raw or binhex encoded string

See also [hash_final](http://php.net/manual/en/function.hash-final.php)

int openssl_digest_size(string method)
---
Returns the digest size, in bytes, of the specified method.

Example: `openssl_digest_size('sha1') == 20`

int openssl_digest_block_size(string method)
---
Returns the block size, in bytes, of the specified method.

Example: `openssl_digest_size('md5') == 64`

resource openssl_digest_copy(resource ctx)
---
Returns a copy of the digest hash context.

Example:

	$a = openssl_digest_init('md5');
	openssl_digest_update($a, 'the fox ');
	$b = openssl_digest_copy($a);
	openssl_digest_update($a, 'jumped');
	openssl_digest_update($b, 'escaped');
	echo openssl_digest_final($a); // == md5('the fox jumped')
	echo openssl_digest_final($b); // == md5('the fox escaped')

resource openssl_encrypt_init(string method, string password [, long options=0 [, string $iv='']])
---
Creates and returns a encryption context for given method and key  
**Note: the `OPENSSL_RAW_DATA` flag is ignored as base64 encoded output is not supported**  It is recommended that scripts still set the `OPENSSL_RAW_DATA` flag in case this behaviour changes in the future

See also [openssl_encrypt](http://php.net/manual/en/function.openssl-encrypt.php)

string openssl_encrypt_update(resource ctx, string data)
---
Encrypts given data using given encryption context, returns raw string

As data may be processed in blocks, this function may return an empty string

string openssl_encrypt_final(resource ctx)
---
Returns any remaining data from encrypting context, and cleans everything up

resource openssl_decrypt_init(string method, string password [, long options=0 [, string $iv = '']])
---
Creates and returns a decryption context for given method and key  
*Note: the `OPENSSL_RAW_DATA` flag is ignored as base64 encoded input is not supported*  It is recommended that scripts still set the `OPENSSL_RAW_DATA` flag in case this behaviour changes in the future

See also [openssl_decrypt](http://php.net/manual/en/function.openssl-decrypt.php)

string openssl_decrypt_update(resource ctx, string data)
---
Decrypts and returns given raw data using given decryption context

string openssl_decrypt_final(resource ctx)
---
Returns any remaining data from decrypting context, and cleans everything up

int openssl_cipher_block_size(string method)
---
Returns the block size, in bytes, of the specified method.

Example: `openssl_cipher_block_size('aes-256-cbc') == 16`

int openssl_cipher_key_length(string method)
---
Returns the key length, in bytes, of the specified method.

Example: `openssl_cipher_key_length('aes-256-cbc') == 32`

See also [openssl_cipher_iv_length](http://php.net/manual/en/function.openssl-cipher-iv-length.php) (which this method somewhat complements)

int openssl_cipher_mode(string method)
---
Returns the block mode of the specified method.  The return value will equal one (or more, if OR'd together) of the following OPENSSL_CIPH_* constants:

* OPENSSL_CIPH_STREAM_CIPHER
* OPENSSL_CIPH_ECB_MODE
* OPENSSL_CIPH_CBC_MODE
* OPENSSL_CIPH_CFB_MODE
* OPENSSL_CIPH_OFB_MODE
* OPENSSL_CIPH_CTR_MODE
* OPENSSL_CIPH_GCM_MODE
* OPENSSL_CIPH_CCM_MODE
* OPENSSL_CIPH_XTS_MODE
* OPENSSL_CIPH_WRAP_MODE

Example: `openssl_cipher_mode('aes-256-cbc') == OPENSSL_CIPH_CBC_MODE`

Example
===
	<?php
	// open input file
	$fr = fopen('some_big_file', 'rb');
	// we'll encrypt this file to the following output
	$fw = fopen('encrypted_file', 'wb');
	
	// generate an IV
	$iv = openssl_random_pseudo_bytes(openssl_cipher_iv_length('aes-128-cbc'));
	// write the IV to the file so it can be decrypted later
	fwrite($fw, $iv);
	// initialise encryption
	$enc = openssl_encrypt_init('aes-128-cbc', md5('My Password', true), 0, $iv);
	
	// for demonstration purposes, also calculate the SHA1 hash of the input file
	$hash = openssl_digest_init('sha1');
	
	// read through the file
	while(!feof($fr)) {
		$buffer = fread($fr, 16384);
		
		fwrite($fw, openssl_encrypt_update($enc, $buffer));
		openssl_digest_update($hash, $buffer);
	}
	// push out any remaining data
	fwrite($fw, openssl_encrypt_final($enc));
	fclose($fr); fclose($fw);
	
	echo "Hash of file is", openssl_digest_final($hash), "\n";

