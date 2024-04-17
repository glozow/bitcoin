26.2rc1 Release Notes
==================

Bitcoin Core version 26.2rc1 is now available from:

  <https://bitcoincore.org/bin/bitcoin-core-26.2/test.rc1/>

This release includes new features, various bug fixes and performance
improvements, as well as updated translations.

Please report bugs using the issue tracker at GitHub:

  <https://github.com/bitcoin/bitcoin/issues>

To receive security and update notifications, please subscribe to:

  <https://bitcoincore.org/en/list/announcements/join/>

How to Upgrade
==============

If you are running an older version, shut it down. Wait until it has completely
shut down (which might take a few minutes in some cases), then run the
installer (on Windows) or just copy over `/Applications/Bitcoin-Qt` (on macOS)
or `bitcoind`/`bitcoin-qt` (on Linux).

Upgrading directly from a version of Bitcoin Core that has reached its EOL is
possible, but it might take some time if the data directory needs to be migrated. Old
wallet versions of Bitcoin Core are generally supported.

Compatibility
==============

Bitcoin Core is supported and extensively tested on operating systems
using the Linux kernel, macOS 11.0+, and Windows 7 and newer.  Bitcoin
Core should also work on most other Unix-like systems but is not as
frequently tested on them.  It is not recommended to use Bitcoin Core on
unsupported systems.

Notable changes
===============

### Script

- #29853: sign: don't assume we are parsing a sane TapMiniscript

### P2P and network changes

- #29691: Change Luke Dashjr seed to dashjr-list-of-p2p-nodes.us

### RPC

- #29869: rpc, bugfix: Enforce maximum value for setmocktime
- #28554: bugfix: throw an error if an invalid parameter is passed to getnetworkhashps RPC

### Build

- #29747: depends: fix mingw-w64 Qt DEBUG=1 build

### Misc

- #29776: ThreadSanitizer: Fix #29767
- #29856: ci: Bump s390x to ubuntu:24.04
- #29764: doc: Suggest installing dev packages for debian/ubuntu qt5 build

Credits
=======

Thanks to everyone who directly contributed to this release:

- Antoine Poinsot
- dergoegge
- fanquake
- Jameson Lopp
- laanwj
- Luke Dashjr
- MarcoFalke
- nanlour
