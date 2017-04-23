Kuznyechik and Magma Linux Kernel Modules
=========================================
This is an implementation of Kuznyechik and Magma encryption algorithms for using in the Linux Crypto API. Implementation of Kuznyechik is based on [Markku-Juhani O. Saarinen's implementation](https://github.com/mjosaarinen/kuznechik) but SSE optimization has been replaced by portable code in order allow easy integration into the Linux kernel. Source code of Magma originates from the [Colin Plumb's implementation](https://www.schneier.com/sccd/GOST-PLU.ZIP) of older soviet cipher `GOST 28147-89` (from which Magma is derived).

Kuznyechik and Magma are two symmetric encryption algorithms designed by Russian Federal Security Service (FSB) and approved as National Standard of the Russian Federation (`GOST R 34.12-2015`) in 2015. Kuznyechik can be pretty much considered as newer Russian counterpart to well-known American AES.


## How to Use
The implementation contains configuration for DKMS. By running `sudo make install` it will add and install it as DKMS module so `kuznyechik.ko` and `magma.ko` kernel modules should be recompiled automatically after your kernel upgrade.

To uninstall, run `sudo make uninstall`.


## License
This program is licensed under MIT license.
