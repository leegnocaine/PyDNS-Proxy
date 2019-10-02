# PyDNS-Proxy
Single file python DNS proxy that supports UDP, TCP and DOH

This is a very simple python script that solves personal needs for better control over how to resolve your DNS.
Through JSON config file, you can separate domains into three different categories, each of them has a group of DNS servers which you can specify.
It also has a simple private host resolve function and a redirect query function, and on special cases you can config to filter off some of the domains' IPV4 query result.

It serves on UDP port, it supports IPV6. The script itself can do UDP and TCP query on its own with just standard python libs.
DOH requires HTTP/2, so if you want to do DOH query, you need to install hyper module.

Hyper is a HTTP/2 client lib for python.
By default hyper uses its built-in pure-Python HPACK encoder and decoder, which is not that efficient for DNS querie.
So if you want to increase the performance, install nghttp2 library for the system and also install its python bindings, hyper will transparently switch to using nghttp2‘s HPACK implementation instead of its own.

For Hyper, read more on https://hyper.readthedocs.io/
For nghttp2, read more on https://nghttp2.org


About JSON config file:

IMPORTANT: The script does NOT convert any letter cases, it requires lower case letters in the config.

"xxx_dns_querymode": only "udp", "tcp" or "doh"

"xxx_dns_server": use "#" to indicate port number

"private_host": for each domain, resolved CNAME starts with "!"


