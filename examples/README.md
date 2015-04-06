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

If you want to time certain actions before or after the server does something based on a signal it received you can hook your own functions into the signal handling of the endless server.

There is a `PRE_SIGNAL` and a `POST_SIGNAL` hook dor each signal. These are exposed as lists of parameterless functions:

    func preSigUsr1() {
	    log.Println("pre SIGUSR1")
    }

If you want to have this function executed before `SIGUSR1` you would add it to the hooks like this:

	srv := endless.NewServer("localhost:4244", mux)
	srv.SignalHooks[endless.PRE_SIGNAL][syscall.SIGUSR1] = append(
		srv.SignalHooks[endless.PRE_SIGNAL][syscall.SIGUSR1],
		preSigUsr1)

then build, and run it

    $ go build -o hook_server examples/hook.go
    $ ./hook_server
    2015/04/06 20:32:13 1489 localhost:4244

now send `SIGUSR1`

    kill -SIGUSR1 1489

and you should see something like this

    2015/04/06 20:33:07 pre SIGUSR1
    2015/04/06 20:33:07 1489 Received SIGUSR1.
    2015/04/06 20:33:07 post SIGUSR1


## Running several servers (eg on several ports)

This is probably less useful as you could always run separate servers - but in case you need to start more than one listener from one binary it will also work with endless - pretty much the same way it works in the simple and TLS examples.
