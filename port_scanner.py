import socket
import nmap

from common_ports import ports_and_services


def get_open_ports(target, port_range, verbose=False):

    open_ports = []
    ip = socket.gethostbyname(target)
    port = '-'.join(map(str, port_range))
    print("address:", ip, port)
    scan = nmap.PortScanner()

    return (open_ports)


def main():
    pass
    # get_open_ports("", [440, 450], True)


if __name__ == "__main__":
    main()
