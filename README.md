# Rakelimit

A multi-dimensional fair-share rate limiter in BPF, designed for UDP.
The algorithm is based on Hierarchical Heavy Hitters, and ensures that no party can exceed
a certain rate of packets. For more information please take a look at our [blog post](https://blog.cloudflare.com/building-rakelimit/).

## Usage

First we need to increase the optmem memory

```
sudo sysctl -w net.core.optmem_max=65536
```

To activate rakelimit create a new instance and provide a file descriptor and a rate limit that you think the
service in question won't be able to handle anymore:

```go

address, err := net.ResolveUDPAddr("udp4", ":9876")
if err != nil {
    log.Fatal("b", err)
}

connection, err := net.ListenUDP("udp4", address)
if err != nil {
	log.Fatal("a", err)
}

// our service can handle 128 packets per second
ppsPerSecond := 128
rake, err := New(connection, ppsPerSecond)
defer rake.Close()
```

That's all! The library now enforces rate limits on incoming packets, and it happens within the kernel.

## Limitations
- no IPv6 (we're working on adding it)
- requires tweaking of optmem
- not production ready