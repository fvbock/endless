# endless

Zero downtime restarts for golang HPTT and HTTPS servers.

## Inspiration & Credits

Well... it's what you want right - no need to hook in and out on a loadbalancer or something - just compile, SIGHUP, start new one, finish old requests etc.

There is https://github.com/rcrowley/goagain and i looked at https://fitstar.github.io/falcore/hot_restart.html which looked easier to do, but still some assembly required. I wanted something that's ideally as simple as

    err := endless.ListenAndServe("localhost:4242", mux)

I found the excellent post [Graceful Restart in Golang](http://grisha.org/blog/2014/06/03/graceful-restart-in-golang/) by [Grisha Trubetskoy](https://github.com/grisha) and took his code as a start. So a lot of credit to Grisha!


## Features

- Drop-in replacement for `http.ListenAndServe` and `http.ListenAndServeTLS`
- Signal hooks to execute your own code before or after the listened to signals (SIGHUP, SIGUSR1, SIGUSR2, SIGINT, SIGTERM, SIGTSTP)


## TODOs

- make the hooks system work properly (overridable defaults and access to the server instance))
- tests
- documentation
- less ugly wrapping of the tls.listener
- maybe also support for SP (scalable protocols - nanomsg or mangos)?


## Examples

are in https://github.com/fvbock/endless/tree/master/examples
