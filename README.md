# HAProxy with ModSecurity Integration

## Build

We need to have rust, libmodsecurity-dev, and clang installed

``` sh
sudo apt install rustc libmodsecurity-dev clang
```

You can also install rust from rustup.

After than, build the library with

``` sh
cargo build
```

## Run

Start HAProxy with
``` sh
haproxy -d -f haproxy.cfg
```

Visiting http://httpbin.test.localhost:8080/get?foo=block-me will result in an error page
