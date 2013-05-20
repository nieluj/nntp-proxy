# nntp-proxy

simple NNTP proxy with SSL support. If a padlock engine is available, it will be used automatically for AES encryption (requires libssl > 1.0).

## Configuration

Below is an example of a configuration file :

```
##################################
#
# nntp-proxy configuration
#
##################################

nntp_server:
{
    # NNTP Server host and port address
    server = "ssl-eu.astraweb.com";
    port = 563;
    # NNTP username
    username = "changeme";
    # NNTP password in clear text
    password = "changeme";
    # Maximum number of connections allowed by the NNTP
    max_connections = 20;
};

proxy:
{
    #Local address and port to bind to
    bind_ip = "0.0.0.0";
    bind_port = 5555;

    # SSL key and cert file
    ssl_key = "key.pem";
    ssl_cert = "cert.pem";

    # Verbose levels: ERROR, WARNING, NOTICE, INFO, DEBUG
    verbose = "INFO";

    # Password is made with: 'mkpasswd -m sha-512 <password>'
    # mkpasswd is found in whois package on Debian-based systems
    users = (
        {
            # Username of the client side of the proxy
            username = "tarzan";
            # Password: monkey
            password = "$6$Ds77DJE/u/ScJLk$Tj0SaT7AUDdDBqS7v/4uDYGYWDDH3GWSL0KP6FQKk7anC5Cghi5IJUYzIAxJZ8rFgyeFmosPSEyQRL.slG5ST1";
            # the number of allowed connections for this user
            max_connections = 1;
        },
        {
            # Username of the client side of the proxy
            username = "jane";
            # Password: king
            password = "$6$xvOO3Cm97/O6yj$a6GmSiz9yWCibWcetxJQ.c4cIOUbXly.3i1p/oCqdGo47TezmChb0tSeIxmvD.2zrb/lywc4vtl/IKLBoqMXs1";
            # the number of allowed connections for this user
            max_connections = 1;
        }
    );
};
```



## Installation

TODO

### Compilation

The program relies on ``libevent`` (version 2) with openssl support and libconfig. On Debian-based systems, the dependencies can be installed with the following command line :

```sh
$ sudo apt-get install libssl-dev libevent-dev libconfig-dev
```

On Mac OS X

```sh
$ brew install openssl libevent libconfig pkg-config
$ brew link --force openssl
```

The provided `Makefile` can be used to compile the program.

### SSL support

The proxy only establishes SSL connections to the NNTP and with the NNTP clients.
A X509 certificate must be generated for the server side of the proxy

```sh
$ openssl genrsa -out key.pem 2048
$ openssl req -new -key key.pem -out cert.req
$ openssl x509 -req -days 365 -in cert.req -signkey key.pem -out cert.pem
```

## Usage

`nntp-proxy [<config file>]`

  * `config file` : Configuration file (See nntp-proxy.conf.example)

Example : `$ nntp-proxy nntp-proxy.conf`

## Troubleshooting

The first thing to try is to test a connection using OpenSSL :

```bash
$ openssl s_client -host localhost -port 563
CONNECTED(00000003)
depth=0 CN = localhost
verify error:num=18:self signed certificate
verify return:1
depth=0 CN = localhost
verify return:1
---
Certificate chain
 0 s:/CN=localhost
   i:/CN=localhost
---
Server certificate
-----BEGIN CERTIFICATE-----
MIICpDCCAYwCCQDj2QNMky6R8zANBgkqhkiG9w0BAQUFADAUMRIwEAYDVQQDDAls
b2NhbGhvc3QwHhcNMTMwNTIwMTAxODEyWhcNMTQwNTIwMTAxODEyWjAUMRIwEAYD
[...]
j4IpsG3kPxY5ONX9JvdggnKkYEvI1DKQTPKM1EwkuWLe/H0rZRE1nA12aQD45lyp
3oVSa8TiQwBlCT9C2y63mW4m3E7v70jwSm5JnuxovqAefgZ76n7VYGtl7lGOgfxD
L8MPr0uN0XA=
-----END CERTIFICATE-----
subject=/CN=localhost
issuer=/CN=localhost
---
No client certificate CA names sent
---
SSL handshake has read 1017 bytes and written 568 bytes
---
New, TLSv1/SSLv3, Cipher is AES256-SHA
Server public key is 2048 bit
Secure Renegotiation IS supported
Compression: zlib compression
Expansion: zlib compression
SSL-Session:
    Protocol  : TLSv1.1
    Cipher    : AES256-SHA
    Session-ID: 2A56CC5DC4DFB9D1D113CB8447914D07DF0359E3958472F8BB49877BC329DDF5
    Session-ID-ctx: 
    Master-Key: 4EC9F096762531815FEA4BF97F86A12040FAA94D7208994298D5D73F2553622FB1B1A790FF528D68D394E23F6466345B
    Key-Arg   : None
    PSK identity: None
    PSK identity hint: None
    SRP username: None
    TLS session ticket lifetime hint: 300 (seconds)
    TLS session ticket:
    0000 - 97 d1 d6 6f 45 8e 5b ce-03 81 f0 5f 8e 54 c2 d4   ...oE.[...._.T..
    0010 - 18 a4 5d 47 80 89 42 44-32 0f 93 99 4b 30 04 fb   ..]G..BD2...K0..
    0020 - f4 0d be 83 05 b6 5a 84-62 77 ae dd e1 13 50 83   ......Z.bw....P.
    0030 - 3f 3b de 14 ad 6f 60 ef-89 fc 17 c5 4e 21 51 95   ?;...o`.....N!Q.
    0040 - de fa 8a 3e 35 0c 6b 48-ca 51 12 12 a4 12 3f bf   ...>5.kH.Q....?.
    0050 - 91 5f e0 92 71 94 56 79-26 39 e6 03 8a 9d b9 32   ._..q.Vy&9.....2
    0060 - 5f 35 da a1 f6 c6 1b 0d-a2 20 d6 f9 48 ee bd dc   _5....... ..H...
    0070 - 8d 18 0b 54 6c 15 3e e1-a2 55 50 b0 22 08 65 ff   ...Tl.>..UP.".e.
    0080 - 40 0d c4 77 84 fc 24 5d-76 20 43 0c 2d 79 61 32   @..w..$]v C.-ya2
    0090 - d5 84 00 4e 5f f9 c9 4f-02 ad 23 85 d5 c2 8c 0c   ...N_..O..#.....

    Compression: 1 (zlib compression)
    Start Time: 1369045956
    Timeout   : 300 (sec)
    Verify return code: 18 (self signed certificate)
---
200 NNTP Proxy service ready.
AUTHINFO USER tarzan
381 PASS required
AUTHINFO PASS monkey
281 OK
LIST EXTENSIONS
202 Extensions supported:
HDR
OVER
.
```
