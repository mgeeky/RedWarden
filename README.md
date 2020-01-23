# proxy2

Easily extensible HTTP/HTTPS proxy.


## Features

* easy to customize
* require no external modules
* support both of IPv4 and IPv6
* support HTTP/1.1 Persistent Connection
* support dynamic certificate generation for HTTPS intercept
* support for custom packets handling plugins (by means of request/response/save handlers)

This script works on Python 2.7.
You need to install OpenSSL at your machine to intercept HTTPS connections.
Program will be trying to utilize `openssl` command from your system.


## Usage

You can invoke the program with following options:

```
Usage: proxy2.py [options]

Options:
  --version             show program's version number and exit
  -h, --help            show this help message and exit
  -v, --verbose         Displays verbose output along with packets' contents
                        dumping/tracing.
  -d, --debug           Displays debugging informations (implies verbose
                        output).
  -s, --silent          Surpresses all of the output logging.
  -w PATH, --output=PATH
                        Specifies output log file.
  -H NAME, --hostname=NAME
                        Specifies proxy's binding hostname. Default:
                        localhost.
  -P NUM, --port=NUM    Specifies proxy's binding port number. Default: 8080.
  -t SECS, --timeout=SECS
                        Specifies timeout for proxy's response in seconds.
                        Default: 5.
  -u URL, --proxy-url=URL
                        Specifies proxy's self url. Default:
                        http://proxy2.test/.
  -S, --no-ssl          Turns off SSL interception routines and falls back on
                        relaying.

  SSL Interception setup:
    --ssl-certdir=DIR   Sets the destination for all of the SSL-related files,
                        including keys, certificates (self and of the visited
                        websites). Default: "certs/"
    --ssl-cakey=NAME    Sets the name of a CA key file's name. Default:
                        "ca.key"
    --ssl-cacert=NAME   Sets the name of a CA certificate file's name.
                        Default: "ca.crt"
    --ssl-certkey=NAME  Sets the name of a CA certificate key's file name.
                        Default: "cert.key"
    --ssl-cacn=CN       Sets the common name of the proxy's CA authority.
                        Default: "proxy2 CA"

  Plugins handling:
    -p PATH, --plugin=PATH
                        Specifies plugin's path to be loaded. Every plugin's
                        module must implement class `ProxyHandler' and
                        respectively: `request_handler' and `response_handler'
                        class methods that will get called.One can find
                        example of such plugin in plugins/dummy.py.
```

The simplest usage is like the following:

```
$ python proxy2.py
```

Which will setup SSL interception just-in-time (meaning will use `openssl` which must be located in the system) by generating CA certificate, keys, and create relevant directory for gathered certificates from visited webservers. Below output presents sample session:

```
[INFO] 14:41:29: Preparing SSL certificates and keys for https traffic interception...
[INFO] 14:41:29: Serving HTTP Proxy on: 127.0.0.1, port: 8080...
[INFO] 14:43:13: Request: "https://google.com/"
[INFO] 14:43:13: Request: "https://www.google.pl/?gfe_rd=cr&ei=garVVtnOCqeO6ASe84jwCg"
```


## HTTPS interception

HTTPS interception is being setup automatically, just in time during program's initialization phase. It consists of generation of private keys and a private CA certificate. However, if `openssl` cannot be located on a machine, one can turn off interception by specyfing:

```
$ python proxy2.py -S
```

or in other means configure proxy2.py to point it with proper SSL-related files. For more information please refer to the program's help. 

Through the proxy, you can access http://proxy2.test/ and install the CA certificate in the browsers.


## Customization

You can easily customize the proxy and modify the requests/responses or save something to the files.
The ProxyRequestHandler class has 3 methods to override:

* request_handler: called before accessing the upstream server
* response_handler: called before responding to the client
* save_handler: called after responding to the client with the exclusive lock, so you can safely write out to the terminal or the file system

By default, only save_handler is implemented which outputs HTTP(S) headers and some useful data to the standard output.

You can implement your own packets handling plugin by implementing `ProxyHandler` class with methods listed above. Then, you'll have to point the program at your plugin with -p option.



## Known bugs

- Generating SSL certificates on the fly as implemented in `ProxyRequestHandler.generate_ssl_certificate()` fails on Windows most likely due to openssl's error "__unable to write 'random state'__". This needs further investigation.