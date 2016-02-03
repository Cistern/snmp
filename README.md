snmp [![Circle CI](https://circleci.com/gh/Cistern/snmp.svg?style=svg&circle-token=6a02882a38de80ca5628580d3579c2dd32242321)](https://circleci.com/gh/Cistern/snmp) [![GoDoc](https://godoc.org/github.com/PreetamJinka/snmp?status.svg)](https://godoc.org/github.com/PreetamJinka/snmp) [![BSD License](https://img.shields.io/pypi/l/Django.svg)](https://github.com/PreetamJinka/snmp/blob/master/LICENSE)
====

An [SNMP](http://en.wikipedia.org/wiki/Simple_Network_Management_Protocol) v3 client library for Go.

This package only supports SNMP v3 with authPriv mode using SHA authentication and AES encryption.
Only 128-bit AES is supported.

SNMP sessions are goroutine-safe. One of the goals of this package is to be able to handle
sessions with many (> 100) devices concurrently.

API guarantees
---
API stability is *not guaranteed*. Vendoring or using a dependency manager is suggested.

License
---
BSD (see LICENSE)
