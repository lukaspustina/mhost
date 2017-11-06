# mhost

The primary objective of `mhost` is to perform DNS queries similar to the Unix `host` command line tool. In contrast to `host`, `mhost` queries multiple servers in parallel and compares their results. That way you can check, if queried DNS servers return the same results.

There are different situations in which DNS servers might return deviating results. The most simple case is caches which have not yet been updated. After a zone updates, it takes time until DNS servers around the world pick up the changes. Another case is misconfiguration of a zone's primary DNS server and failed AXFR zone transfers. Last, but not least, an internet service provider or any other authority might want to silently divert your request to another target.

In all these cases, `mhost` can help you to figure out what's going on.

## Use Cases

### Use Operating System's default Resolver and Google's public DNS servers

`mhost -s 8.8.8.8 -s 8.8.4.4 github.com`

### Use 100 DNS German Servers from [ungefiltert-surfen](https://www.ungefiltert-surfen.de)

`mhost -u de github.com`

### Output JSON for post-processing

`mhost -u de -o json github.com`


## Thanks

Thanks to [Benjamin Fry](https://github.com/bluejekyll) for his literally wonderful [TRust-DNS](http://trust-dns.org) server and the corresponding client library which does all the heavy lifting of `mhost`.

