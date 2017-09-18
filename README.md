# mhost

The primary objective of `mhost` is to lookup DNS queries similar to the Unix `host` command line tool. In contrast to `host`, `mhost` queries multiple server parallel and compares their results. In this way, you can check, if queried DNS servers return the same results.

There are different situation in which DNS servers might return deviating results. The most simple case it caches which have not yet been updated. After a zone updates, it takes time until DNS servers around the world pick up the changes. Another case is misconfiguration of zone's primary DNS server and failed AXFR zone transfers. Last, but not least, a internet service provider or any other authority might want to silently divert your request to another target.

In all these cases, `mhost` can help you to figure out what's going on.

## Use Cases

### Use Operating System's default Resolver and Google's public DNS servers

`mhost -s 8.8.8.8 -s 8.8.4.4 github.com`

### Use 100 DNS German Servers from [ungeflitert-surfen](https://www.ungefiltert-surfen.de)

`mhost -u de github.com`

### Output JSON for Post-Processing

`mhost -u de -o json github.com`


## Thanks

Thanks to [Benjamin Fry](https://github.com/bluejekyll) for his literally wonderful [TRust-DNS](http://trust-dns.org) server and the corresponding client library which does all the heaving lifting of `host`.

