
all: man1/mhost.1

man1/mhost.1: mhost.1.md man1 pandoc
	@pandoc -s -t man $< -o $@
	@sed -i.bk 's/\.TH.*/.TH "mhost" "1"/g' man1/mhost.1
	@rm -f man1/mhost.1.bk

man1:
	@mkdir $@

pandoc:
	@pandoc --version > /dev/null

view: man1/mhost.1
	@man -M . 1 mhost

clean:
	@-rm -R man1

.PHONY: pandoc view clean

