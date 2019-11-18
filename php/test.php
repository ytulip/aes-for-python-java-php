<?php
require_once  './pkcs7Encoder.php';
require_once  './sha1.php';


$encodeKey = 'abcdefghijklmnopqrstuvwxyz0123456789ABCDEFG';
$crypt = new Prpcrypt($encodeKey);
$res = $crypt->encrypt('{"errcode":1,"data":"测试数据"}');
$timestamp = time();
$nonce = $crypt->getRandomStr(6);
$signature = (new SHA1())->getSHA1($encodeKey, $timestamp, $nonce, $res[1])[1];
// 加签
echo '{"data":"'. $res[1] .'","timestamp":"'.$timestamp.'","nonce":"'.$nonce.'","signature":"'.$signature.'"}';
exit;