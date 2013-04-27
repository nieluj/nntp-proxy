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
    port = 5555;

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

`nntp-proxy [<config file>]'

  * `config file` : Configuration file (See nntp-proxy.conf.example)

Example : `$ nntp-proxy nntp-proxy.conf`
