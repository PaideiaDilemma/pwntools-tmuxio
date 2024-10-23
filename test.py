from pwn import *
from tmuxio import tmuxio
import time
import os


def test_kmaze():
    test_elf = context.binary = ELF("kmaze", checksec=False)

    io = tmuxio([test_elf.path], x=64, y=64)
    assert io.tmux.has_session()

    maze = io.capture_pane(start=0, end=200)
    print(maze)
    time.sleep(
        1
    )  # without attaching will resize tmux and capture pane might not be finished yet.

    io.sendline(b"w")
    io.sendline(b"a")
    io.sendline(b"s")
    io.sendline(b"d")

    io.tmux_attach()


def test_basic_io():
    io = tmuxio(["python -c 'print(input())'"])
    assert io.tmux.has_session()

    io.sendline(b"Hello World\nasdf")
    assert b"Hello World" in io.readuntil(b"Hello World")

    io.readline()
    io.close()


def test_arbitrary_bytes():
    read_bytes_c_code = """
#include <stdio.h>
#include <unistd.h>

int main() {
    char buf[1024];
    int n = read(0, buf, 1024);

    for (int i = 0; i < n; i++) {
        printf("%02x ", buf[i]);
    }
    printf("\\n");
}
"""

    print(read_bytes_c_code)
    with open("read_bytes.c", "w") as f:
        f.write(read_bytes_c_code)

    os.system("cc read_bytes.c -o read_bytes")

    io = tmuxio(["./read_bytes"])

    io.sendline(b"\x01\x02\x03\x04\x05\x06\x07\x08\x09")
    # io.sendline(b"\x01\x02\x03\x04\x05\x06\x07\x08\x09")
    print(io.readline())

    io.tmux_attach()

    # io.close()


if __name__ == "__main__":
    test_kmaze()
    test_arbitrary_bytes()
    test_basic_io()
