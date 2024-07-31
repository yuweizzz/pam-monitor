# sshd-monitor

An eBPF-based tool to deny network packets and collect weak passwords.

Use for learning eBPF.

## Get Started

``` bash
# Usage
$ ./sshd-monitor -h
Usage of ./sshd-monitor:
  -c string
    	config file (default "conf.toml")

# Run
$ ./sshd-monitor -c conf.toml
```

`conf.toml`:

``` bash
PamLib = "/lib/x86_64-linux-gnu/libpam.so.0"

# net filter
NetIface = "enp0s3"
MaxFailedCount = 3
TimeUnit = 60
ReportPeriod = 30

# Weak password dictionary
BuildDictOnly = false
Users = [
    "root",
    "mysql",
]
```

`sshd-monitor` will monitor the PAM authentication event and log the host that failed. Based on the number of failed attempts, it will determine whether to accept or deny packets from those hosts. It will also continuously collect a weak password dictionary.

Use `BuildDictOnly = true` to disable the net filter feature and build the weak password dictionary quickly.

## Build

Dependencies:

* golang
* make
* clang
* llvm
* gcc
* linux-headers

``` bash
# Use Debian 12

# install golang
$ apt install make clang llvm gcc linux-headers-amd64
$ make
```

## License

[MIT license](https://github.com/yuweizzz/sshd-monitor/blob/main/LICENSE)
