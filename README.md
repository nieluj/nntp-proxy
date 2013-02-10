# nntp-proxy

simple NNTP proxy with SSL support. If a padlock engine is available, it will be used automatically for AES encryption (requires libssl > 1.0).

## Configuration

For the time being, the configuration data is directly in the source file `nntp-proxy.c`. Below is an example configuration :

```C
/** Configuration part **/

/* Username needed to establish the connection to the NNTP server */
#define SERVER_USER "FIXME"
/* Password associated to username */
#define SERVER_PASS "FIXME"
/* Maximum number of connections allowed by the NNTP */
#define MAX_CONNS 20

/* Login / passwords for the client side of the proxy, the password is generated with  'mkpasswd -m sha-512' */
/* The last field is the number of allowed connections for this user */
struct user_info users[] = {
    { "foo", "$6$aBUzpyBd$TNZv2jzHtARuoUPQmVjxRSHBZPKniMuZIUzAAd8Ob1c5pzcExsTDfA9zCF.sN8pmZL0Cb48FW/7iEtang7wBg/", 1 },
    { NULL, NULL, 0 }
};

/** end of configuration **/
```

Obviously, the program needs to be recompiled after modifying these values.

## Installation

### Compilation

The program relies on ``libevent`` (version 2) with openssl support. On Debian-based systems, the dependencies can be installed with the following command line :

```sh
$ sudo apt-get install libssl-dev libevent-dev 
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

The program accepts the following arguments:

  * `keypath` : the path to the private key file
  * `certpath` : the path to the certificate file
  * `listen-on-addr` : the local address and port to bind to 
  * `connect-to-addr` : the NNTP server address to connect to

Example : `$ nntp-proxy key.pem cert.pem 0.0.0.0:563 ssl-eu.astraweb.com:443`
