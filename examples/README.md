# Examples

## Simple server

compile the example

    $ go build -o simple_server examples/simple.go

run it

    $ ./simple_server
    2015/03/22 20:03:29 PID: 2710 localhost:4242

make a request

    $ curl http://localhost:4242/hello
    WORLD!

change the handler - eg. replace the `!` with a `?`

    $ go build -o simple_server examples/simple.go
    $ kill -1 2710

the server log says something like:

    2015/03/22 20:04:10 2710 Received SIGHUP. forking.
    2015/03/22 20:04:10 2710 Received SIGTERM.
    2015/03/22 20:04:10 2710 Waiting for connections to finish...
    2015/03/22 20:04:10 PID: 2726 localhost:4242
    2015/03/22 20:04:10 accept tcp 127.0.0.1:4242: use of closed network connection
    2015/03/22 20:04:10 Server on 4242 stopped

make another request

    $ curl http://localhost:4242/hello
    WORLD?


## Running several servers (eg on several ports)

TODO

## Hooking into the signal handling

TODO
