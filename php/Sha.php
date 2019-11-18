<?php
require_once  './pkcs7Encoder.php';
require_once  './sha1.php';

$signature = (new SHA1())->getSHA1('abcdefghijklmnopqrstuvwxyz0123456789ABCDEFG', 1569293758, '5Ehivc', '2RxnU1A7lrsmK8YgOgFIUEJ4swj/rJ+M5K1qGYlVK4kkcaXBYNXok2fhv9SRRNZcFKc400Yv6mALeOQDurKVjg==')[1];
var_dump($signature);
exit;