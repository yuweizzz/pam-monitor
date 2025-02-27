# pam-monitor

An eBPF-based tool to deny network packets and collect weak passwords.

Use for learning eBPF.

## Get Started

``` bash
# Usage
$ ./pam-monitor -h
Usage of ./pam-monitor:
  -c string
    	config file (default "conf.toml")

# Run
$ ./pam-monitor -c conf.toml
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

## Update weak password dictionary

Updated [weak password dictionary](https://github.com/yuweizzz/pam-monitor/blob/main/dictionary.txt) in 2025/2/28.

Use `cat dictionary.txt | sort | uniq >> new_dictionary.txt` to remove duplicates.

Please make sure your password not in it, use `grep root:your_password dictionary.txt` to check.

## License

[MIT license](https://github.com/yuweizzz/pam-monitor/blob/main/LICENSE)
