# !/usr/bin/env python
# -*- coding: utf-8 -*-
from Crypt import Prpcrypt, SHA1
import time

if __name__ == "__main__":
    encodingAESKey = "abcdefghijklmnopqrstuvwxyz0123456789ABCDEFG"
    crypt = Prpcrypt(encodingAESKey)
    res = crypt.encrypt('我摔倒了')
    print('密文:')
    print(res)

    # 加签名
    snonce = crypt.get_random_str(4)
    sha1 = SHA1()
    timestamp = str(int(time.time()))
    signature = sha1.getSHA1(encodingAESKey, timestamp, snonce ,res[1])
    print('签名:')
    print(signature)


    ret = crypt.decrypt(res[1])
    print('解密:')
    print(ret[1].decode())
