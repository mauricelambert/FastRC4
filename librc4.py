#!/usr/bin/env python3
# -*- coding: utf-8 -*-

###################
#    This module implements a python interface for librc4
#    Copyright (C) 2023, 2024  Maurice Lambert

#    This program is free software: you can redistribute it and/or modify
#    it under the terms of the GNU General Public License as published by
#    the Free Software Foundation, either version 3 of the License, or
#    (at your option) any later version.

#    This program is distributed in the hope that it will be useful,
#    but WITHOUT ANY WARRANTY; without even the implied warranty of
#    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
#    GNU General Public License for more details.

#    You should have received a copy of the GNU General Public License
#    along with this program.  If not, see <https://www.gnu.org/licenses/>.
##################

"""
This module implements a python interface for librc4
"""

__version__ = "0.0.2"
__author__ = "Maurice Lambert"
__author_email__ = "mauricelambert434@gmail.com"
__maintainer__ = "Maurice Lambert"
__maintainer_email__ = "mauricelambert434@gmail.com"
__description__ = "This module implements a python interface for librc4"
license = "GPL-3.0 License"
__url__ = "https://github.com/mauricelambert/FastRC4"

copyright = """
FastRC4  Copyright (C) 2023, 2024  Maurice Lambert
This program comes with ABSOLUTELY NO WARRANTY.
This is free software, and you are welcome to redistribute it
under certain conditions.
"""
__license__ = license
__copyright__ = copyright

__all__ = []

print(copyright)

from ctypes import cdll, c_char_p, c_ulonglong, cast, c_void_p
from os import urandom, name


class RC4:
    r"""
    RC4 class to implement librc4.so interface for python.

    I recommend you to use encrypt and decrypt methods not default_* methods.
    /!\ For untrusted data you must always use encrypt and decrypt methods.
    """

    def __init__(self, key: bytes):
        self.key = key
        if name != "nt":
            arc4 = self.arc4 = cdll.LoadLibrary("./librc4.so")
        else:
            arc4 = self.arc4 = cdll.LoadLibrary(".\\librc4.dll")

        arc4.get_iv.restype = c_void_p
        self.default_generate_iv = arc4.generate_iv
        self.default_xor_key_iv = arc4.xor_key_iv
        self.default_reset_key = arc4.reset_key
        self.default_get_iv = lambda: self._read_all_buffer(
            cast(arc4.get_iv(), c_char_p), 256
        )

    def encrypt(self, data: bytes, iv: bytes = b"") -> bytes:
        """
        This function encrypts data with the RC4 key and a random IV.

        IV should be 256 bytes long.
        """

        data_length = len(data)
        iv = iv + urandom(256 - len(iv))
        self.arc4.reset_key()
        self.arc4.generate_key(c_char_p(self.key))
        self.arc4.set_iv(c_char_p(iv))
        self.arc4.xor_key_iv()
        cipher = c_char_p(data)
        self.arc4.arc4(cipher, c_ulonglong(data_length))
        return (
            data_length.to_bytes(8, "big") + iv + cipher._objects[:data_length]
        )  # self._read_all_buffer(cipher, data_length)

    def decrypt(self, data: bytes, safe: bool = True) -> bytes:
        """
        This function decrypts data with the RC4 keys.
        """

        iv = data[8:264]
        cipher = data[264:]
        cipher_length = (
            int.from_bytes(data[:8], "big") if not safe else len(cipher)
        )

        if not safe and cipher_length != len(cipher):
            raise ValueError("Invalid data length found.")

        self.arc4.reset_key()
        self.arc4.generate_key(c_char_p(self.key))
        self.arc4.set_iv(c_char_p(iv))
        self.arc4.xor_key_iv()
        data = c_char_p(cipher + b"\0")
        self.arc4.arc4(data, c_ulonglong(cipher_length))
        return data._objects[
            :cipher_length
        ]  # self._read_all_buffer(data, cipher_length)

    def default_encrypt(self, data: bytes, length: int = 0) -> bytes:
        """
        This function is the interface for the default encrypt function (in the DLL).

        If length is 0, the encrypt function cipher string terminating by null byte.
        """

        cipher = c_char_p(data + b"\0")
        self.arc4.encrypt(c_char_p(self.key), cipher, c_ulonglong(length))
        return cipher._objects[
            : length if length else len(data)
        ]  # self._read_all_buffer(cipher, len(data))

    def default_decrypt(self, iv: bytes, cipher: bytes, length: int) -> bytes:
        """
        This function is the interface for the default decrypt function (in the DLL).
        """

        data = c_char_p(cipher + b"\0")
        self.arc4.decrypt(
            c_char_p(self.key), c_char_p(iv), data, c_ulonglong(length)
        )
        return data._objects[
            :length
        ]  # self._read_all_buffer(data, len(cipher))

    def default_arc4_null_byte(self, data: bytes) -> bytes:
        """
        This function is the interface for the default arc4_null_byte function (in the DLL).
        """

        cipher = c_char_p(data + b"\0")
        self.arc4.arc4_null_byte(cipher)
        return cipher._objects[
            : len(data)
        ]  # self._read_all_buffer(cipher, len(data))

    def default_arc4(self, data: bytes, length: int = None) -> bytes:
        """
        This function is the interface for the default arc4 function (in the DLL).

        If length is None this function set length to len(data).
        """

        length = len(data) if length is None else length
        cipher = c_char_p(data + b"\0")
        self.arc4.arc4(cipher, c_ulonglong(length))
        return cipher._objects[
            :length
        ]  # self._read_all_buffer(cipher, length)

    def default_generate_key(self) -> None:
        """
        This function is the interface for the default generate_key function (in the DLL).
        """

        self.arc4.generate_key(c_char_p(self.key))

    def default_set_iv(self, iv: bytes) -> None:
        """
        This function is the interface for the default set_iv function (in the DLL).

        IV must be 256 bytes long.
        """

        if len(iv) != 256:
            raise ValueError("IV must be 256 bytes long not " + str(len(iv)))

        self.arc4.set_iv(c_char_p(iv))

    @staticmethod
    def _read_all_buffer(buffer: c_char_p, length: int) -> bytes:
        """
        This function reads full buffer termating with null byte (work with null byte inside).
        """

        data = buffer.value
        while len(data) < length:
            data += b"\0"
            buffer = cast(
                c_void_p.from_buffer(buffer).value + len(buffer.value) + 1,
                c_char_p,
            )
            data += buffer.value
        # assert len(data) == length, str(len(data)) + " " + str(length) + " " + repr(data)
        return data


def tests():
    ##############################
    #  TEST 1: Random IV
    ##############################
    # Problem: there is only one IV by execution

    from PythonToolsKit.DataAnalysis import DataAnalysis

    data = []

    iv_generator = RC4(b"")
    for i in range(256):
        data.append({i: 0})
    for i in range(10000):
        iv_generator.default_generate_iv()  # always the same IV
        for random_byte in iv_generator.default_get_iv():
            data.append({random_byte: 1})

    analyzer = DataAnalysis(data)
    analyze = list(analyzer.keys_frequences())
    analyzer.statistictypes_printer(analyze)
    print("Max:", max(analyze, key=lambda x: x.value))
    print("Min:", min(analyze, key=lambda x: x.value))
    analyzer.statistictypes_chart(analyze)

    from binascii import hexlify

    key = b"This is my secret key !"
    iv = urandom(256)
    data = b"This is my secret data ! " + hexlify(bytes(range(256)))

    ##############################
    #  TEST 2: Secure encryption
    ##############################
    # Problem: Cipher greater than data

    rc4 = RC4(key)

    cipher = rc4.encrypt(data)
    print("Cipher:", len(cipher), cipher)
    uncipher = rc4.decrypt(cipher)
    print("Secret (safe):", uncipher)
    uncipher = rc4.decrypt(cipher, safe=False)
    print("Secret (unsafe):", uncipher)

    print("reset key")
    rc4.default_reset_key()

    ##############################
    #  TEST 3.1: Default encryption
    ##############################
    # Problem: don't work after test 2 but working good if i don't run the test 2

    key = b"This is my secret key !"
    data = b"This is my secret data ! " + hexlify(bytes(range(256)))

    rc4 = RC4(key)

    print("Data:", len(data), data)
    cipher = rc4.default_encrypt(data, len(data))
    print("Cipher:", len(cipher), cipher)
    new_iv = rc4.default_get_iv()
    print("IV:", len(new_iv), new_iv)
    rc4.default_reset_key()
    secret = rc4.default_decrypt(new_iv, cipher, len(data))
    print("Secret:", len(secret), secret)

    print("reset key")
    rc4.default_reset_key()

    ##############################
    #  TEST 3.2: Default encryption
    ##############################
    # Problem: don't work after test 2 but working good if i don't run the test 2

    key = b"This is my secret key !"
    data = b"This is my secret data ! " + hexlify(bytes(range(256)))

    rc4 = RC4(key)

    print("Data:", len(data), data)
    cipher = rc4.default_encrypt(data)
    print("Cipher:", len(cipher), cipher)
    new_iv = rc4.default_get_iv()
    print("IV:", len(new_iv), new_iv)
    rc4.default_reset_key()
    secret = rc4.default_decrypt(new_iv, cipher, len(data))
    print("Secret:", len(secret), secret)

    print("reset key")
    rc4.default_reset_key()

    ################################
    #  TEST 4: Low level encryption
    ################################
    # Problem: don't work after another encryption but working good if is the first encryption

    key = b"This is my secret key !"
    data = b"This is my secret data ! " + hexlify(bytes(range(256)))

    rc4 = RC4(key)

    print("generate_key")
    rc4.default_generate_key()
    print("iv")
    rc4.default_generate_iv()
    print("get_iv")
    new_iv = rc4.default_get_iv()
    print("IV 1:", len(new_iv), new_iv)
    print("xor_key_iv")
    rc4.default_xor_key_iv()
    print("arc4 null byte")
    cipher = rc4.default_arc4_null_byte(data)
    print("Cipher:", len(data), len(cipher), cipher)

    print("reset_key")
    rc4.default_reset_key()

    print("generate_key")
    rc4.default_generate_key()
    print("set_iv")
    rc4.default_set_iv(new_iv)
    print("xor_key_iv")
    rc4.default_xor_key_iv()
    print("default_arc4")
    uncipher = rc4.default_arc4(cipher)
    print("Secret:", len(uncipher), uncipher)

    ##############################
    #  TEST 5: Different IV
    ##############################
    # Problem: this is the same IV generated

    rc4 = RC4(key)

    print("generate_iv")
    rc4.default_generate_iv()
    other_iv = rc4.default_get_iv()
    print("IV 2:", len(other_iv), other_iv)
    print("pass")

    ##############################
    #  TEST 6: Test RC4 compatibility with other encryption services
    ##############################
    #

    rc4 = RC4(b"mykey")
    rc4.default_reset_key()
    rc4.default_generate_key()
    cipher1 = rc4.default_arc4(b"mydata" * 256)
    print("Encryption from librc4:", cipher1.hex())

    from urllib.request import urlopen, Request
    from json import load, dumps

    cipher2 = load(
        urlopen(
            Request(
                "https://www.lddgo.net/api/RC4?lang=en",
                headers={"Content-Type": "application/json;charset=UTF-8"},
                data=dumps(
                    {
                        "inputContent": "mydatamydatamydatamydatamydatamydatamydatamydatamydatamydatamydatamydatamydatamydatamydatamydatamydatamydatamydatamydatamydatamydatamydatamydatamydatamydatamydatamydatamydatamydatamydatamydatamydatamydatamydatamydatamydatamydatamydatamydatamydatamydatamydatamydatamydatamydatamydatamydatamydatamydatamydatamydatamydatamydatamydatamydatamydatamydatamydatamydatamydatamydatamydatamydatamydatamydatamydatamydatamydatamydatamydatamydatamydatamydatamydatamydatamydatamydatamydatamydatamydatamydatamydatamydatamydatamydatamydatamydatamydatamydatamydatamydatamydatamydatamydatamydatamydatamydatamydatamydatamydatamydatamydatamydatamydatamydatamydatamydatamydatamydatamydatamydatamydatamydatamydatamydatamydatamydatamydatamydatamydatamydatamydatamydatamydatamydatamydatamydatamydatamydatamydatamydatamydatamydatamydatamydatamydatamydatamydatamydatamydatamydatamydatamydatamydatamydatamydatamydatamydatamydatamydatamydatamydatamydatamydatamydatamydatamydatamydatamydatamydatamydatamydatamydatamydatamydatamydatamydatamydatamydatamydatamydatamydatamydatamydatamydatamydatamydatamydatamydatamydatamydatamydatamydatamydatamydatamydatamydatamydatamydatamydatamydatamydatamydatamydatamydatamydatamydatamydatamydatamydatamydatamydatamydatamydatamydatamydatamydatamydatamydatamydatamydatamydatamydatamydatamydatamydatamydatamydatamydatamydatamydatamydatamydatamydatamydatamydatamydatamydatamydatamydatamydatamydatamydatamydatamydatamydatamydatamydatamydatamydatamydatamydatamydatamydatamydatamydatamydatamydatamydatamydatamydatamydatamydatamydatamydata",
                        "inputPassword": "mykey",
                        "charset": "UTF-8",
                        "inputFormat": "string",
                        "outputFormat": "hex",
                        "encrypt": True,
                    }
                ).encode(),
            )
        )
    )["data"]
    print("Encryption from lddgo.net:", cipher2)
    print("Ciphers are equals:", cipher1.hex() == cipher2)


if __name__ == "__main__":
    from sys import exit

    exit(tests())
