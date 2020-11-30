trade-balancer
==============

trade-balancer is:

- a self-contained C websocket client
- using Linux Kernel TLS
- for load balancing inbound [Polygon.io trade](https://polygon.io/) messages
- sent across pipes
- to a forked worker process
- and the worker process itself can fork more worker processes for concurrent pipe processing

Status: stable. This server has run for months unattended. It gracefully handles network
outages, disconnects, and reconnects to continue processing the upstream trade feed as aggressively as possible.

For a full write-up, check out my article [Load Balancing Stock Market Trades From A WebSocket Feed](https://matt.sh/load-balance-trades).

Building / Running
------------------
`trade-balancer` is Linux-only because we take advantage of Linux 4.17+ being able to handle
TLS encryption and decryption transparently in the kernel, plus we take advantage of
Linux being able to allocate pipe buffers as large as 2 GB (most other platforms limit pipes
to 64 KB max), plus we also enjoy using `PR_SET_PDEATHSIG` to clean up child processes.

`trade-balancer` is also gcc-only because we like to use endian-defined structs for the websocket header.


Start by increasing your system maximum pipe size:
```bash
echo 0 > /proc/sys/fs/pipe-user-pages-soft
echo 0 > /proc/sys/fs/pipe-user-pages-hard
echo 2147483648 > /proc/sys/fs/pipe-max-size
```

The value 2147483648 is `2^31 (or 1 << 31)` and it's the maximum as enforced by the kernel
proc setting function [round_pipe_size()](https://github.com/torvalds/linux/blob/3dd0130f2430decf0cb001b452824515436986d2/fs/pipe.c#L1211-L1225)

Next, verify you are on a 4.17+ kernel with the tls module compiled and loaded:
```bash
modprobe tls
```

Next, populate the `mbedtls` submodule if it isn't already populated:
```bash
git submodule init; git submodule checkout
```

Now we should be ready to build:
```bash
mkdir build
cd build
cmake ..
make -j12
```

If everything compiled, you're almost ready to have something working.

There are some variables and settings inside the code you need to modify to get your own platform working:

- modify your subscription symbols inside `subscribe()` (currently just set to the entire market, usually less than 10 GB per day)
- as the last command line parameters, specify the child process to be forked with pipe references
    - the child process will receive one command line argument for each pipe count you specify
        - e.g. if you run `./lb key wss://server/stocks 6 /tmp ./xtro abc`, your child process will launch with six pipe fd arguments like: `./xtro abc 2 4 6 8 10 12` inside directory `/tmp`
        - then your child process uses the command line argument integers to listen on those inbound pipes for trade JSON messages
        - the protocol for the pipes is: [4-byte little endian length][data]
        - using python, you can read a 4-byte prefix protocol like (if `self` here is the inbound pipe):
        ```python
            async def readWithHeader(self):
                header = await self.read(4)
                totalLen = int.from_bytes(header, byteorder="little")
                totalRead = 0
                result = io.BytesIO()
                while totalRead < totalLen:
                    got = await self.read(totalLen - totalRead)
                    totalRead += len(got)
                    result.write(got)

                # orjson doesn't like the memoryview from .getbuffer()
                # restore .getbuffer() when orjson doesn't fail with " Input must be bytes, bytearray, or str:"
                # return result.getbuffer()
                return result.getvalue()
        ```

Running:
```bash
./lb [polygon auth key] [polygon endpoint URL] [number of pipes to create] [working directory for worker executable] [worker executable path] [worker executable args...]
```

Examples:
```bash
./lb AZ8jfdjslkfdjs wss://alpaca.socket.polygon.io/stocks 57 ~/bin/ ~/bin/stock-analysis.py
./lb AZ8jfdjslkfdjs wss://socket.polygon.io/stocks 31 ~/repos/stock/ /usr/local/bin/pipenv run ~/repos/stock/analyze.py
./lb AZ8jfdjslkfdjs wss://delayed.polygon.io/stocks 79 /mnt/data-storage ./only-log-from-pipes
./lb AZ8jfdjslkfdjs ws://127.0.0.1:9943/dev-replay-api 27 ~/repos/stock /usr/local/bin/pipenv run ~/repos/stock/analyze.py
```

Caveats
-------

We take advantage of a couple facts to help our processing:

- we expect our server to be trusted and non-hostile (not sending malformed websocket protocol framing, etc)
- we treat websocket text and binary frames the same (some clients try to UTF-8 validate text frames which is wasted processing time when just consuming a streaming JSON API for forwarding)
- we don't parse the JSON into individual native types; we treat JSON as just text to scan over.
- we expect (read: require) inbound trade JSON to always start with the same field and spacing layout since we jump over initial fields by byte offsets
- we expect production to run over TLS, so we don't care about the websocket anti-middlebox protections like xor sending and using WebSocket-Key for anti-cache-replay protection
- our per-message pipe protocol is just [4-byte little endian unsigned integer length][DATA] because all data we send over pipes is individual JSON trade objects less than 150 bytes each

History
-------
I wanted to consume the [Polygon WebSocket feed](https://polygon.io/sockets), which is a live feed of every
trade on every US stock exchange, in real time for analysis and trade decisions.  After a couple weeks
of failing to get Python to cooperate as the load balancer due to allocation+websocket+json+forwarding delays,
it ended up being more efficient to write a new websocket client in C and have it do all the text processing without Python overhead.

Using Linux TLS capability is a great performance helper since we can write unencrypted
content to the kernel and receive unencrypted content back transparently. This avoids needing to do the
typical workflow of: generate our data, allocate an encryption buffer, run encryption, send encrypted data to
the kernel, free original data and encrypted data, receive encrypted data from the kernel, allocate space for unencrypted
data, run-decryption, free encrypted data and unencrypted data. Now we just do regular `send()` and `recv()` calls
and the kernel writes unencrypted data directly into the `recv()` buffer for our process (also making the application logic completely
agnostic to whether encryption is being used).

The downside of kernel TLS is it _only_ handles the encryption and decryption of an established TLS session, so we
must manually run the TLS handshake ourself. Big thanks to https://github.com/zliuva/ktlswrapper for having a live
example of how to run TLS handshake then extract the encryption metadata to initialize the kernel TLS metadata.

Any questions? Feel free to open an issue or drop me an email.
