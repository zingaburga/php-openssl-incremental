<?php

@ini_set('memory_limit', '256M');
@set_time_limit(300);

$mb = 80; // size
$data = str_repeat("\0", $mb*1048576);

function bench($f, $args, $extra='') {
	global $mb;
	
	$t = microtime(true);
	$ret = call_user_func_array($f, $args);
	$t = microtime(true) - $t;
	
	if($extra) $f .= " ($extra)";
	echo str_pad($f, 30);
	echo ": fingerprint = ", substr(md5($ret), 24), ";\tspeed = ", number_format($mb/$t, 3), " MB/s\n";
}

// Hash tests
bench('sha1', array($data, true));
bench('hash', array('sha1', $data, true), 'sha1');
bench('openssl_digest', array($data, 'sha1', true), 'sha1');
echo "---\n";
bench('hash', array('sha256', $data, true), 'sha256');
bench('openssl_digest', array($data, 'sha256', true), 'sha256');
echo "---\n";
bench('md5', array($data, true));
bench('hash', array('md5', $data, true), 'md5');
bench('openssl_digest', array($data, 'md5', true), 'md5');
echo "---\n";

// Encryption tests
$key = md5('', true);
$iv = $key;

if(function_exists('mcrypt_encrypt') && defined('MCRYPT_RIJNDAEL_128')) {
	bench('mcrypt_encrypt', array(MCRYPT_RIJNDAEL_128, $key, $data, MCRYPT_MODE_CBC, $iv), 'aes');
}
bench('openssl_encrypt', array($data, 'aes-128-cbc', $key, OPENSSL_RAW_DATA | OPENSSL_ZERO_PADDING, $iv), 'aes');
/*
echo "---\n";
if(function_exists('mcrypt_encrypt') && defined('MCRYPT_RC4')) {
	bench('mcrypt_encrypt', array(MCRYPT_RC4, $key, $data, MCRYPT_MODE_STREAM), 'rc4');
}
bench('openssl_encrypt', array($data, 'rc4', $key, OPENSSL_RAW_DATA | OPENSSL_ZERO_PADDING), 'rc4');
*/
