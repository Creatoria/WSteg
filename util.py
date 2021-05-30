import numpy as np
from scipy.io import wavfile
from Crypto.Cipher import AES
from Crypto.PublicKey import RSA
from Crypto.Signature import pkcs1_15
from Crypto.Hash import SHA256
from Crypto.Util.Padding import pad, unpad
from Crypto.Util.strxor import strxor
import random
import struct
from reedsolo import RSCodec
import warnings
import os
from pywt import dwt, idwt

warnings.filterwarnings('ignore')

_check = 32
_rsc_block = 255 - _check
_header_size = 32
MODE_PLAIN = 0
MODE_AES = 1

__all__ = ['Cryp', 'EMess', 'embeed', 'extract', 'estimate']


class EMess():
    def __init__(self, text: bytes) -> None:
        self.text = text
        self.nn = 0
        self.bn = 0
        self.blen = len(text) * 8

    def __iter__(self):
        return self

    def __next__(self):
        if self.nn * 8 + self.bn > self.blen:
            raise StopIteration
        cc = bin(self.text[self.nn])[2:].zfill(8)[self.bn]
        self.bn += 1
        if self.bn == 8:
            self.nn += 1
            self.bn = 0
        return cc

    def __len__(self):
        return len(self.text)

    def __eq__(self, tt: object) -> bool:
        return self.text == tt


class Cryp():
    def __init__(self, mode=None, debug=False, password=None, verify=False, key=None, **kwargs):
        if password is not None:
            self.mode = MODE_AES
        elif mode is None:
            pass
        else:
            self.mode = MODE_PLAIN
            self.block_size = 16
        if self.mode == MODE_AES:
            if isinstance(password, bytes):
                self.cipher = AES.new(
                    pad(password, 16), AES.MODE_CBC, bytes(16))
            elif isinstance(password, str):
                self.cipher = AES.new(
                    pad(password.encode(), 16), AES.MODE_CBC, bytes(16))
            else:
                raise TypeError('Unknown key type')
            self.block_size = self.cipher.block_size
        if self.mode not in [0, 1]:
            raise TypeError('Unknown encryption mode')
        self.verify = verify
        self.debug = debug
        if self.verify:
            if key is None:
                raise Exception('no key provided')
            self.key = RSA.import_key(open(key).read())

    def decrypt(self, data: bytes, hashalg=SHA256):
        broken = False
        try:
            bb = self._unhead(data[:_header_size])
        except:
            print(data)
            return b'\x00', True
        _rrs = RSCodec(_check)
        dd = data[_header_size:bb * 255 + _header_size]
        if self.debug:
            print(_rrs.check(dd))
        kd = b''
        for i in range(bb):
            try:
                kd += _rrs.decode(dd[i * 255:(i + 1) * 255])[0]
            except:
                kd += dd[i * 255:(i + 1) * 255 - _check]
                broken = True
        try:
            dd = unpad(kd, _rsc_block)
        except:
            dd = kd[:-kd[-1]]
            broken = True
        if self.mode == MODE_AES:
            dd = self._aes_dec(dd)
        else:
            dd = dd
        try:
            dd = unpad(dd, self.block_size)
        except:
            dd = dd[:-dd[-1]]
            broken = True
        if self.verify:
            sz = self.key.size_in_bytes()
            dd, sig = dd[:-sz], dd[-sz:]
            hs = hashalg.new(dd)
            try:
                pkcs1_15.new(self.key).verify(hs, sig)
                print('signature verified')
            except:
                print('signature not valid')
        if broken:
            print('data may be broken during the process')
        return dd, broken

    def encrypt(self, data: bytes, hashalg=SHA256):
        if self.verify:
            if not self.key.has_private():
                raise AttributeError('not a private key')
            hs = hashalg.new(data)
            sig = pkcs1_15.new(self.key).sign(hs)
            ee = pad(data + sig, self.block_size)
        else:
            ee = pad(data, self.block_size)
        if self.mode == MODE_AES:
            ee = self._aes_enc(ee)
        else:
            pass
        return self._ehead(ee)

    def _ehead(self, data: bytes):
        header = b'WsTeg\x01\x02\x03'
        ee = pad(data, self.block_size)
        ll = struct.pack('i', 1 + len(ee) // self.block_size)
        _rrs1 = RSCodec()
        _rrs2 = RSCodec(_check)
        return _rrs1.encode(pad(header + ll, _header_size - 10)) + _rrs2.encode(pad(data, _rsc_block))

    def _unhead(self, hh: bytes):
        _rrs = RSCodec()
        try:
            hd = _rrs.decode(hh)[0]
        except:
            print('broken header')
            hd = hh[:-10]
        if hd[:5] != b'WsTeg':
            raise Exception('Unknown header type')
        ll = 1 + int.from_bytes(hd[8:12], 'little') * \
            self.block_size // _rsc_block
        return ll

    def _aes_enc(self, data: bytes):
        return self.cipher.encrypt(data)

    def _aes_dec(self, data: bytes):
        return self.cipher.decrypt(data)


def extract(audiofile: str, ths=2048, perseg=441, overlap=0):
    pass


def embeed(mess: EMess, infile: str, outfile: str, ths=2048, perseg=441, overlap=0):
    pass


def _bin2byt(s: str):
    d = b''
    while len(s) >= 8:
        ct = int(s[:8], 2).to_bytes(1, 'little')
        d += ct
        s = s[8:]
    return d


def estimate(audiofile: str, ths=2048, perseg=441, overlap=0):
    pass


def mis(out, raw):
    st = len(raw) - len(out)
    rt = raw[:len(out)]
    mi = EMess(strxor(out, rt))
    cc = 0
    i = 0
    while i < len(mi) * 8:
        cc += int(next(mi))
        i += 1
    return st / len(raw), cc / len(out) / 8


if __name__ == '__main__':
    infile = 'test/wavs/01.wav'
    outfile = 'out.wav'
    privk = 'test/test.key'
    pubk = 'test/test.pub.key'
    # print(estimate(infile), 'bytes available.')

    # c = Cryp()
    # d = Cryp(debug=True)

    c = Cryp(MODE_AES, password=b'123456')
    d = Cryp(MODE_AES, password=b'123456')

    # c = Cryp(MODE_AES, password=b'123456',
    #            verify=True, key=privk)
    # d = Cryp(MODE_AES, password=b'123456',
    #            verify=True, key=pubk)

    # mm = random.randbytes(2048)
    mm = b'hello' * 200
    ee = c.encrypt(mm)
    # print(ee, len(ee))
    embeed(EMess(ee), infile, outfile, ths=1600)
    # os.system('ffmpeg -i out.wav -b:a 320k o1.mp3 -y')
    # os.system('ffmpeg -i o1.mp3 o2.wav -y')
    dd = extract('out.wav', ths=1600)
    # print(dd[:len(ee)], len(dd))
    dd, fg = d.decrypt(dd)
    los, ber = mis(dd, mm)
    # print(dd)
    print(dd == mm, 'lost={},ber={}'.format(los, ber))
