import socket
import nmap

from common_ports import ports_and_services


def get_open_ports(target, port_range, verbose=False):

    open_ports = []

    # Check if IP or Hostname target for getting the correct IP address.
    # Gaierror gives the same error, but due to the tests to differentiate between an IP address or hostname error.
    if any(char.isdigit() for char in target):
        try:
            # print("Integer test")
            ip_address = socket.gethostbyname(target)

        # Here we throw the error invalid IP address.
        except socket.gaierror:
            print("Error: Invalid IP address")
            return "Error: Invalid IP address"
    else:
        try:
            # print("String test")
            ip_address = socket.gethostbyname(target)

        # Here we throw the error invalid hostname.
        except socket.gaierror:
            print("Error: Invalid hostname")
            return "Error: Invalid hostname"

    # Port can be [440,445], so string join - and both ports
    port_str = '-'.join(map(str, port_range))

    print("address:", ip_address, port_str)
    scanner = nmap.PortScanner()  # Creating the nmap port scanner.
    print("Nmap Version:", scanner.nmap_version())
    scanner.scan(ip_address, port_str)
    print(scanner.scaninfo())
    print("Ip Status: ", scanner[ip_address].state())
    # Returns a list of all protocols
    protocols = scanner[ip_address].all_protocols()
    print("Detected protocols: ", protocols)
    for protocol in protocols:
        # Iterating the result and retrieve only the ports that is open, ignoring the ones that is filtered or closed..
        for port in scanner[ip_address][protocol].keys():
            if scanner[ip_address][protocol][port]['state'] == 'open':
                # Appending them to my open_ports list
                open_ports.append(port)
                print("Open TCP port:", port)

    # Print more detailed info if verbose true
    if verbose:
        # Standard output
        try:
            hostname = socket.gethostbyaddr(ip_address)[0]
            verbose_output = f"Open ports for {hostname} ({ip_address})\nPORT     SERVICE\n"

        # In case if the ip address does not have a hostname. We need another output
        except socket.herror:
            verbose_output = f"Open ports for {ip_address}\nPORT     SERVICE\n"

        for port in open_ports:
            # Using the ports and services dict.
            service_name = ports_and_services.get(port)
            verbose_output += f"{port}      {service_name}\n"
            print(verbose_output)
        return verbose_output.rstrip()
    else:
        return open_ports


def main():
    # # get_open_ports("266.255.9.10", [440, 450], True)  # Failure ip
    # get_open_ports("scanme.nmap", [440, 450], True)  # Failure hostname
    # get_open_ports("scanme.nmap.org", [20, 80], True)  # Correct hostname
    get_open_ports("104.26.10.78", [440, 450], True)  # Correct ip


if __name__ == "__main__":
    main()
