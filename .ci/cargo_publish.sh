#!/bin/sh

echo "Upgrading OpenSSL because 'cargo publish' runs outside of cross containers and trust dns needs at least openssl 1.0.2"
wget http://security.ubuntu.com/ubuntu/pool/main/o/openssl/libssl1.0.0_1.0.2g-1ubuntu4.6_amd64.deb
wget http://security.ubuntu.com/ubuntu/pool/main/o/openssl/libssl-dev_1.0.2g-1ubuntu4.6_amd64.deb

sudo dpkg -i libssl1.0.0_1.0.2g-1ubuntu4.6_amd64.deb
sudo dpkg -i libssl-dev_1.0.2g-1ubuntu4.6_amd64.deb

echo "Cleaning working directory"
git clean -f -x
echo "Publishing to crates.io"
cross publish --token "$1"

