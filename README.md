# Rakelimit

A multi-dimensional fair-share rate limiter in BPF, designed for UDP.
The algorithm is based on Hierarchical Heavy Hitters, and ensures that no party can exceed
a certain rate of packets. For more information please take a look at our [blog post](https://blog.cloudflare.com/building-rakelimit/).

## Usage

To activate rakelimit create a new instance and provide a file descriptor and a rate limit that you think the
service in question won't be able to handle anymore:

```go

conn, err := net.ListenPacket("udp4", "127.0.0.1:0")
if err != nil {
    tb.Fatal("Can't listen:", err)
}
udpConn := conn.(*net.UDPConn)

// We don't want to allow anyone to use more than 128 packets per second
ppsPerSecond := 128
rake, err := New(udpConn, ppsPerSecond)
defer rake.Close()
// rate limiter stays active even after closing
```

That's all! The library now enforces rate limits on incoming packets, and it happens within the kernel.

## Requirements

The library should be go-gettable, and has been tested on Linux 5.11.

You may have to increase optmem_max depending on your distribution:

```
sudo sysctl -w net.core.optmem_max=22528
```

You will need a `clang-12` binary if you want to recompile the filter. Simply run `go generate` in the root of the project.

## Limitations
- IPv6 doesn't support options
- requires tweaking of optmem
- not tested in production

## Testing

```
go test .
```
