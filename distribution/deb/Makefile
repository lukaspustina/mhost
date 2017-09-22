BASE_NAME=mhost
BIN_NAME=mhost

all:
	@echo 'Example: SRC_DIR=../../ BIN=../../target/release/$(BIN_NAME) ARCH=amd64 VERSION=0.1.0-alpha-3 TAG=$VERSION DIST=trusty make package'

package: $(BASE_NAME)-$(VERSION)-$(DIST)-$(ARCH).deb

$(BASE_NAME)-$(VERSION)-$(DIST)-$(ARCH).deb: $(BASE_NAME)/DEBIAN/control $(BASE_NAME)/DEBIAN/conffiles $(BASE_NAME)/DEBIAN/postinst $(BASE_NAME)/DEBIAN/prerm $(BASE_NAME)/usr/bin/$(BIN_NAME)
	dpkg-deb -b $(BASE_NAME) $@
	dpkg-deb -I $@

clean:
	-rm -fR $(BASE_NAME)/DEBIAN
	-rm -fR $(BASE_NAME)/usr
	-rm $(BASE_NAME)-$(VERSION)-$(DIST)-$(ARCH).deb

$(BASE_NAME)/DEBIAN/control: templates/DEBIAN/control $(BASE_NAME)/usr/bin/$(BIN_NAME) $(BASE_NAME)/DEBIAN
	SIZE=`du -s $(BASE_NAME)/usr/bin/$(BIN_NAME) | awk '{ print $$1}'`; SANE_VERSION=`echo $$VERSION | sed 's/^[a-z]*//'`; sed "s/@@PACKAGE_NAME@@/$(BASE_NAME)/; s/@@VERSION@@/$${SANE_VERSION}/; s/@@ARCH@@/$(ARCH)/; s/@@SIZE@@/$${SIZE}/" $< > $@

$(BASE_NAME)/usr/bin/$(BIN_NAME): $(BIN) $(BASE_NAME)/usr/bin
	cp $< $@

$(BASE_NAME)/DEBIAN/postinst: templates/DEBIAN/postinst
	cp $< $@
	chmod 755 $@

$(BASE_NAME)/DEBIAN/prerm: templates/DEBIAN/prerm
	cp $< $@
	chmod 755 $@

$(BASE_NAME)/DEBIAN/conffiles: templates/DEBIAN/conffiles
	cp $< $@

$(BASE_NAME)/usr/bin:
	mkdir -p $@

$(BASE_NAME)/DEBIAN:
	mkdir -p $@

