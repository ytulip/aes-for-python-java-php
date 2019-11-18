#!/usr/bin/env python
#-*- encoding:utf-8 -*-
"""
"""
# ------------------------------------------------------------------------

import base64
import string
import random
import hashlib
import time
import struct
from Crypto.Cipher import AES
import xml.etree.cElementTree as ET
import socket
import logging
import ierror


logger = logging.Logger(__name__)

"""
关于Crypto.Cipher模块，ImportError: No module named 'Crypto'解决方案
请到官方网站 https://www.dlitz.net/software/pycrypto/ 下载pycrypto。
下载后，按照README中的“Installation”小节的提示进行pycrypto安装。
"""
class FormatException(Exception):
    pass

def throw_exception(message, exception_class=FormatException):
    """my define raise exception function"""
    raise exception_class(message)

def to_utf8_bytes(str):
    return str.encode("utf8")

def utf8_bytes_to_str(bytes):
    return bytes.decode("utf8")

class PKCS7Encoder():
    """提供基于PKCS7算法的加解密接口"""

    block_size = 32
    def encode(self, text_bytes):
        """ 对需要加密的明文进行填充补位
        @param text_bytes: 需要进行填充补位操作的明文(bytes)
        @return: 补齐明文字符(bytes)
        """
        text_length = len(text_bytes)
        # 计算需要填充的位数
        amount_to_pad = self.block_size - (text_length % self.block_size)
        if amount_to_pad == 0:
            amount_to_pad = self.block_size
        # 获得补位所用的字符
        pad = bytearray([amount_to_pad])
        return text_bytes + pad * amount_to_pad

    def decode(self, decrypted):
        """删除解密后明文的补位字符
        @param decrypted: 解密后的明文
        @return: 删除补位字符后的明文
        """
        pad = ord(decrypted[-1])
        if pad<1 or pad >32:
            pad = 0
        return decrypted[:-pad]

class Prpcrypt(object):
    """提供接收和推送给公众平台消息的加解密接口"""

    def __init__(self,key):
        try:
            self.key = base64.b64decode(key+"=")
            assert len(self.key) == 32
        except:
            throw_exception("[error]: EncodingAESKey unvalid !", FormatException)
        # 设置加解密模式为AES的CBC模式
        self.mode = AES.MODE_CBC


    def encrypt(self,text):
        """对明文进行加密
        @param text: 需要加密的明文
        @return: 加密得到的字符串
        """
        # 16位随机字符串添加到明文开头
        text_bytes = to_utf8_bytes(text)
        text_bytes = to_utf8_bytes(self.get_random_str()) + struct.pack("I", socket.htonl(
            len(text_bytes))) + text_bytes
        # 使用自定义的填充方式对明文进行补位填充
        pkcs7 = PKCS7Encoder()
        text_bytes = pkcs7.encode(text_bytes)
        # 加密
        cryptor = AES.new(self.key,self.mode,self.key[:16])
        try:
            ciphertext = cryptor.encrypt(text_bytes)
            # 使用BASE64对加密后的字符串进行编码
            return ierror.WXBizMsgCrypt_OK, utf8_bytes_to_str(base64.b64encode(ciphertext))
        except Exception as e:
            logger.exception('wechat encryption/decryption error')
            return  ierror.WXBizMsgCrypt_EncryptAES_Error,None

    def decrypt(self,text):
        """对解密后的明文进行补位删除
        @param text: 密文
        @return: 删除填充补位后的明文
        """
        try:
            cryptor = AES.new(self.key,self.mode,self.key[:16])
            # 使用BASE64对密文进行解码，然后AES-CBC解密
            plain_text  = cryptor.decrypt(base64.b64decode(text))
        except Exception as e:
            logger.exception('wechat encryption/decryption error')
            return  ierror.WXBizMsgCrypt_DecryptAES_Error,None
        try:
            pad = plain_text[-1]
            # 去掉补位字符串
            #pkcs7 = PKCS7Encoder()
            #plain_text = pkcs7.encode(plain_text)
            # 去除16位随机字符串
            content = plain_text[16:-pad]
            xml_len = socket.ntohl(struct.unpack("I",content[ : 4])[0])
            xml_content = content[4 : xml_len+4]

        except Exception as e:
            logger.exception('wechat encryption/decryption error')
            return  ierror.WXBizMsgCrypt_IllegalBuffer,None
        return 0,xml_content

    def get_random_str(self, str_len=16):
        """ 随机生成16位字符串
        @return: 16位字符串
        """
        rule = string.ascii_letters + string.digits
        str = random.sample(rule, str_len)
        return "".join(str)

class SHA1:
    """计算公众平台的消息签名接口"""

    def getSHA1(self, token, timestamp, nonce, encrypt):
        """用SHA1算法生成安全签名
        @param token:  票据
        @param timestamp: 时间戳
        @param encrypt: 密文
        @param nonce: 随机字符串
        @return: 安全签名
        """
        try:
            sortlist = [token, timestamp, nonce, encrypt]
            sortlist.sort()
            sha = hashlib.sha1()
            sha.update(to_utf8_bytes("".join(sortlist)))
            return  ierror.WXBizMsgCrypt_OK, sha.hexdigest()
        except Exception as e:
            logger.exception('wechat encryption/decryption error')
            return  ierror.WXBizMsgCrypt_ComputeSignature_Error, None