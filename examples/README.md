# Examples

## Simple server

Compile the example

    $ go build -o simple_server examples/simple.go

Run it

    $ ./simple_server
    2015/03/22 20:03:29 PID: 2710 localhost:4242

Make a request

    $ curl http://localhost:4242/hello
    WORLD!

Change the handler - eg. replace the `!` with a `?`

    $ go build -o simple_server examples/simple.go
    $ kill -1 2710

The server log says something like:

    2015/03/22 20:04:10 2710 Received SIGHUP. forking.
    2015/03/22 20:04:10 2710 Received SIGTERM.
    2015/03/22 20:04:10 2710 Waiting for connections to finish...
    2015/03/22 20:04:10 PID: 2726 localhost:4242
    2015/03/22 20:04:10 accept tcp 127.0.0.1:4242: use of closed network connection
    2015/03/22 20:04:10 Server on 4242 stopped

Make another request

    $ curl http://localhost:4242/hello
    WORLD?


## TLS

Create local cert and key file:

    go run $GOROOT/src/crypto/tls/generate_cert.go --host=localhost

Compile the example

    $ go build -o tls_server examples/tls.go

Run it

    $ ./tls_server
    2015/03/23 19:43:29 PID: 21710 localhost:4242

Make a request (`-k` to disable certificate checks in curl)

    $ curl -k https://localhost:4242/hello
    WORLD!

The rest is like the simple server example: modify the tls.go code, build, send SIGHUP, and make another request.


## Hooking into the signal handling

TODO


## Running several servers (eg on several ports)

This is probably less useful as you could always run separate servers - but in case you need to start more than one listener from one binary it will also work with endless - pretty much the same way it works in the simple and TLS examples.
