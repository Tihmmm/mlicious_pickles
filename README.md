# mlicious_pickles
Dynamically scan pickles for malicious activities during deserialization using eBPF.
<br>
<br>
This PoC has been successfully tested on Ubuntu 24.04.3 LTS AMD64 (kernel version 6.14.0-29-generic).</br>
The first production version is in active development as of 09.15.2025.
## Installation
To install run:</br>
`$ git clone https://github.com/Tihmmm/mlicious_pickles.git`</br>
`$ cd mlicious_pickles/poc`</br>
`$ sudo bpftool btf dump file /sys/kernel/btf/vmlinux format c > vmlinux.h`</br>
`$ sudo make`</br>
</br>
To run run:</br>
`$ sudo make run`</br>
</br>
You can check that it works by running:</br>
`$ python3 pickle/evil_pickle.py`</br>
`$ python3 pickle/victim.py`</br>
Which should trigger an alert written to analyzer's standard output.
