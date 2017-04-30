Kuznyechik and Magma Linux Kernel Modules
=========================================
This is an implementation of Kuznyechik and Magma encryption algorithms for using in the Linux Crypto API. Implementation of Kuznyechik is based on [Markku-Juhani O. Saarinen's implementation](https://github.com/mjosaarinen/kuznechik) but SSE optimization has been replaced by portable code in order allow easy integration into the Linux kernel. Source code of Magma originates from the [Colin Plumb's implementation](https://www.schneier.com/sccd/GOST-PLU.ZIP) of older soviet cipher `GOST 28147-89` (from which Magma is derived).

Kuznyechik and Magma are two symmetric encryption algorithms designed by Russian Federal Security Service (FSB) and approved as National Standard of the Russian Federation (`GOST R 34.12-2015`) in 2015. Kuznyechik can be pretty much considered as newer Russian counterpart to well-known American AES.


## How to Install
The implementation contains configuration for DKMS. By running `sudo make install` it will add and install it as DKMS module so `kuznyechik.ko` and `magma.ko` kernel modules should be recompiled automatically after your kernel upgrade.

To uninstall, run `sudo make uninstall`.


## How to Encrypt a Disk Partition
Linux CryptoAPI modules can be used for full-disk encryption. Let us say you have partition mounted in `/dev/sdb` and you want to encrypt it. In order to be able to do it so, you need to have `cryptsetup` installed on your system. The very first step is to setup your password and format the partition.


```
sudo cryptsetup luksFormat /dev/sdb --cipher=kuznyechik-xts-plain64 \
	--key-size=512 --hash=whirlpool --verify-passphrase
```

This command will format device `/dev/sdb` to a `LUKS` partition. Although Kuznyechik is a 256-bit cipher, when using the `XTS` encryption mode (as used in example), you need to set `--key-size` to `512` (not just `256`) for this mode requires two different 256-bit keys. Keys will be generated automatically and encrypted by another key being derived from your password. Keep in mind that your password is the weakest point of entire system so it should be long, unique, and as random as possible.

After successful format, you need to open new partition that has been created within that original one. Next step is to format it to your favorite file system. After format is done, you can close `cryptsetup`.

```
sudo cryptsetup luksOpen /dev/sdb devname
sudo mkfs.ext4 /dev/mapper/devname
sudo cryptsetup luksClose devname
```

If nothing have broken, you have `/dev/sdb` encrypted now; you can verify it with the `hexdump` utility:


```
sudo hd /dev/sdb -n 112
00000000  4c 55 4b 53 ba be 00 01  6b 75 7a 6e 79 65 63 68  |LUKS....kuznyech|
00000010  69 6b 00 00 00 00 00 00  00 00 00 00 00 00 00 00  |ik..............|
00000020  00 00 00 00 00 00 00 00  78 74 73 2d 70 6c 61 69  |........xts-plai|
00000030  6e 36 34 00 00 00 00 00  00 00 00 00 00 00 00 00  |n64.............|
00000040  00 00 00 00 00 00 00 00  77 68 69 72 6c 70 6f 6f  |........whirlpoo|
00000050  6c 00 00 00 00 00 00 00  00 00 00 00 00 00 00 00  |l...............|
00000060  00 00 00 00 00 00 00 00  00 00 10 00 00 00 00 40  |...............@|
```


## License
This program is licensed under GPL license.
