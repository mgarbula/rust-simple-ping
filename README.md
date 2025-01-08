# Simple ping

Simple ping program which sends one ICMP Echo Request and waits for one response.

To build run 
```
cargo build 
```

To run use
```
sudo ./target/debug/my_ping HOSTNAME
```

Program needs to be run with root privileges in order to open proper socket.