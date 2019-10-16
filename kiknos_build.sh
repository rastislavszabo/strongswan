
./autogen.sh &&
./configure --enable-socket-vpp --enable-libipsec --enable-kernel-vpp \
            --sysconfdir=/etc --with-piddir=/etc/ipsec.d/run \
            --disable-kernel-netlink --disable-socket-default --enable-dhcp &&
make &&
sudo make install
