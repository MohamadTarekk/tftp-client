import sys
import os
import enum
import struct
import socket
from time import sleep


"""
    TFTP packets processing class
"""


class TftpProcessor(object):
    class TftpPacketType(enum.Enum):
        RRQ = 1  # Read request packet
        WRQ = 2  # Write request packet
        DATA = 3  # Data packet
        ACK = 4  # Acknowledgement packet
        ERROR = 5  # Error packet

    def __init__(self, address, expected_packet_type):
        self.source_address = address
        self.expected_packet_type = expected_packet_type
        self.data_buffer = []
        self.error_message = None
        if expected_packet_type == self.TftpPacketType.DATA.value:
            self.block_number = 1
        else:
            self.block_number = 0

    def process_first_packet(self, packet_data, packet_source):
        print(f"Received a packet from {packet_source}")
        # Validate packet source
        if packet_source[0] != self.source_address[0]:
            return self._process_problem(5), False  # discard received packet
        # Get the response packet
        out_packet = self._parse_udp_packet(packet_data)
        # Return suitable ERROR packet if error found
        if out_packet == -1:
            return self._process_problem(4), self.TftpPacketType.ERROR.value
        # Return response packet
        return out_packet, self.expected_packet_type

    def process_udp_packet(self, packet_data, packet_source):
        print(f"Received a packet from {packet_source}")
        # Validate packet source
        if packet_source != self.source_address:
            return self._process_problem(5), False  # discard received packet
        # Get the response packet
        out_packet = self._parse_udp_packet(packet_data)
        # Return suitable ERROR packet if error found
        if out_packet == -1:
            return self._process_problem(4), self.TftpPacketType.ERROR.value
        elif out_packet == -2:
            return self._process_problem(0), self.TftpPacketType.ERROR.value
        # Return response packet
        return out_packet, self.expected_packet_type

    def _parse_udp_packet(self, packet_bytes):
        opcode = self._extract_opcode(packet_bytes)
        if opcode == self.expected_packet_type:
            if (opcode == self.TftpPacketType.DATA.value) \
                    and (len(packet_bytes) > 516):
                return -2
            block_number = self._extract_block_number(packet_bytes)
            if block_number == self.block_number:
                return self._generate_next_packet(opcode)
            elif block_number == (self.block_number - 1):
                return packet_bytes
            else:
                return -1
        elif opcode == self.TftpPacketType.ERROR.value:
            self._parse_server_error(packet_bytes)
        else:
            return -2

    def _generate_next_packet(self, opcode):
        if opcode == self.TftpPacketType.ACK.value:
            # Generate Data Packet
            self.block_number += 1
            data = self.get_next_output_packet()
            format_str = "!HH{}s".format(len(data))
            packet = struct.pack(format_str,
                                 self.TftpPacketType.DATA.value,
                                 self.block_number,
                                 data)
        else:  # opcode == self.TftpPacketType.DATA.value:
            # Generate acknowledge packet
            format_str = "!HH"
            packet = struct.pack(format_str,
                                 self.TftpPacketType.ACK.value,
                                 self.block_number)
            self.block_number += 1
        return packet

    def _process_problem(self, error_code):
        # Set error message
        if error_code == 5:
            error_message = "Unknown transfer ID"
        elif error_code == 4:
            error_message = "Illegal TFTP operation"
        else:
            error_message = "Not defined, Message: Undefined error code"
        # Generate packet
        format_str = "!HH{}sB".format(len(error_message))
        packet = struct.pack(format_str,
                             self.TftpPacketType.ERROR.value,
                             error_code,
                             error_message.encode("ASCII"), 0)
        # Set message to print
        self.error_message = error_message
        return packet

    def _parse_server_error(self, packet):
        error_code = self._extract_block_number(packet)
        print("SERVER ERROR: ", end="")
        if error_code == 0:
            print("Not defined, Message: Undefined error code")
        elif error_code == 1:
            print("File not found!")
        elif error_code == 2:
            print("Access violation!")
        elif error_code == 3:
            print("Disk full or allocation exceeded!")
        elif error_code == 4:
            print("Illegal TFTP operation!")
        elif error_code == 5:
            print("Unknown transfer ID!")
        elif error_code == 6:
            print("File already exists!")
        elif error_code == 7:
            print("No such user!")
        else:
            print("Unknown Error!!!")
        exit(-1)

    @staticmethod
    def _extract_opcode(packet_bytes):
        return struct.unpack("!H", packet_bytes[0:2])[0]

    @staticmethod
    def _extract_block_number(packet_bytes):
        return struct.unpack("!H", packet_bytes[2:4])[0]

    @staticmethod
    def initialize_request(opcode, file_name, mode):
        format_str = "!H{}sB{}sB".format(len(file_name), len(mode))
        request = struct.pack(format_str, opcode,
                              file_name.encode("ASCII"), 0,
                              mode.encode("ASCII"), 0)
        return request

    def set_expected_type(self, expected):
        self.expected_packet_type = expected

    def get_next_output_packet(self):
        return self.data_buffer.pop(0)

    def has_pending_packets_to_be_sent(self):
        return len(self.data_buffer) != 0

    def load_file(self, file_name):
        # Check if file exist
        if not os.path.isfile(file_name):
            print("File not found!")
            exit(-1)
        # Check if file is accessible
        try:
            f = open(file_name, "rb")
        except PermissionError:
            print("Access violation!")
            exit(-1)
        # Load file into memory
        self.data_buffer = []
        file_size = os.stat(file_name).st_size
        buffer_size = 512
        current_size = 0
        while (current_size + buffer_size) < file_size:
            # noinspection PyUnboundLocalVariable
            self.data_buffer.append(f.read(buffer_size))
            current_size = current_size + buffer_size
            pass
        if current_size < file_size:
            current_size = file_size - current_size
            self.data_buffer.append(f.read(current_size))
            pass
        f.close()

    def store_file(self, file_name):
        if self.already_exist(file_name):
            f = open(file_name, "wb")
        else:
            f = open(file_name, "ab")
        while len(self.data_buffer) > 0:
            buffer = self.data_buffer.pop(0)[4:]
            try:
                f.write(buffer)
            except MemoryError:
                print("Disk full or allocation exceeded!")
                exit(-1)
        f.close()

    @staticmethod
    def already_exist(file_name):
        return os.path.isfile(file_name)


"""
    Socket functions
"""


def setup_sockets(address):
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    server_address = (address, 69)
    return sock, server_address


def safe_send(sock, message_packet, server):
    # noinspection PyBroadException
    try:
        sent = sock.sendto(message_packet, server)
        return sent
    except ConnectionError:
        print("Connection cannot be established!")
        exit(-1)
    except Exception:
        print("Cannot establish connection to send")
        exit(-1)


def safe_receive(sock):
    # noinspection PyBroadException
    try:
        received, server = sock.recvfrom(4096)
        return received, server
    except TimeoutError:
        print("Connection timeout")
        exit(-1)
    except Exception:
        print("Cannot establish connection to receive")
        exit(-1)


"""
    Upload function
"""


def push(address, file_name=None):
    # Setup sockets
    sock, server_address = setup_sockets(address)
    # Initialize tftp processor
    tftp_processor \
        = TftpProcessor(server_address, TftpProcessor.TftpPacketType.ACK.value)
    # Load target file
    tftp_processor.load_file(file_name)
    # Initialize WRQ packet
    write_request = tftp_processor.initialize_request(
        tftp_processor.TftpPacketType.WRQ.value, file_name, "octet")
    # Set connection timeout to 10 seconds
    sock.settimeout(3)
    # Try to connect to server and send request packet
    # noinspection PyUnusedLocal
    sent = safe_send(sock, write_request, server_address)
    # Try to receive 1st acknowledgement packet
    received, server = safe_receive(sock)
    # Validate the received packet
    next_packet, packet_type = validate_first_packet(tftp_processor, received, server, sock)
    # Send DATA packets & receive ACK packets
    send_file(tftp_processor, sock, server, next_packet)
    print("\n Done Sending: ", end="")
    print(file_name)


def send_file(tftp_processor, sock, server, next_packet):
    # Set server address
    tftp_processor.source_address = server
    # Send 1st DATA packet
    # noinspection PyUnusedLocal
    sent = safe_send(sock, next_packet, server)
    # Send file
    while tftp_processor.has_pending_packets_to_be_sent():
        # break the loop if there is an error
        next_packet, received = packet_error_check(tftp_processor, sock, server)
        # Send next DATA packet
        # noinspection PyUnusedLocal
        sent = safe_send(sock, next_packet, server)
    sleep(1)


"""
    Download functions
"""


def pull(address, file_name=None):
    # Setup sockets
    sock, server_address = setup_sockets(address)
    # Initialize tftp processor
    tftp_processor \
        = TftpProcessor(server_address, TftpProcessor.TftpPacketType.DATA.value)
    # Initialize RRQ packet
    read_request = tftp_processor.initialize_request(
        tftp_processor.TftpPacketType.RRQ.value, file_name, "octet")
    # Set connection timeout to 10 seconds
    sock.settimeout(3)
    # Try to connect to server and send request packet
    # noinspection PyUnusedLocal
    sent = safe_send(sock, read_request, server_address)
    # Try to receive 1st DATA packet
    received, server = safe_receive(sock)
    # Validate the received packet
    next_packet, packet_type = validate_first_packet(tftp_processor, received, server, sock)
    # Append data to file
    tftp_processor.data_buffer.append(received)
    # If the received file was only one packet
    if len(received) < 516:
        # Send ACK packet
        safe_send(sock, next_packet, server)
        # Save the file
        tftp_processor.store_file(file_name)
        return
    # Receive DATA packets and send ACK packets
    receive_file(tftp_processor, sock, server, next_packet)
    print("\n Done Receiving: ", end="")
    print(file_name)
    tftp_processor.store_file(file_name)
    print(" File saved successfully!")


def receive_file(tftp_processor, sock, server, next_packet):
    # Set server address
    tftp_processor.source_address = server
    # Send 1st ACK packet
    # noinspection PyUnusedLocal
    sent = safe_send(sock, next_packet, server)
    # Receive file
    while True:
        # break the loop if there is an error
        next_packet, received = packet_error_check(tftp_processor, sock, server)
        # Append data to file
        tftp_processor.data_buffer.append(received)
        if len(received) < 516:
            # Send ACK packet
            safe_send(sock, next_packet, server)
            break
        # Send next DATA packet
        # noinspection PyUnusedLocal
        sent = safe_send(sock, next_packet, server)


"""
    Helper functions
"""


def validate_first_packet(tftp_processor, received, server, sock):
    result, packet_type = tftp_processor.process_first_packet(received, server)
    times_received = 1
    while (not packet_type) and (times_received < 5):
        # Send error packet
        # noinspection PyUnusedLocal
        sent = safe_send(sock, result, server)
        print(tftp_processor.error_message)
        # Receive the first ACK packet again
        received, server = safe_receive(sock)
        # Process the received packet
        result, packet_type \
            = tftp_processor.process_first_packet(received, server)
        times_received += 1
    if not packet_type:
        print(tftp_processor.error_message)
        print("Connection timeout!")
        exit(-1)
    if packet_type == tftp_processor.TftpPacketType.ERROR.value:
        # noinspection PyUnusedLocal
        sent = safe_send(sock, result, server)
        print(tftp_processor.error_message)
        sleep(10)
        exit(-1)
    return result, packet_type


def packet_error_check(tftp_processor, sock, server):
    # Receive new packet
    received, source_server = safe_receive(sock)
    # Get next Data packet
    next_packet, packet_type \
        = tftp_processor.process_udp_packet(received, source_server)
    # Make sure the target server received the sent packet
    trial = 1
    while (trial < 5) and (not packet_type):
        # Send error packet to the wrong sender
        # noinspection PyUnusedLocal
        sent = safe_send(sock, next_packet, source_server)
        print(tftp_processor.error_message)
        # Try to receive target server response again
        received, source_server = safe_receive(sock)
        # Get next Data packet
        next_packet, packet_type \
            = tftp_processor.process_udp_packet(received, source_server)
    if not packet_type:
        print(tftp_processor.error_message)
        print("Connection timeout!")
        exit(-1)
    # Check for errors
    if packet_type == tftp_processor.TftpPacketType.ERROR.value:
        # noinspection PyUnusedLocal
        sent = safe_send(sock, next_packet, server)
        print(tftp_processor.error_msg)
        sleep(10)
        exit(-1)
    # Return next packet to send
    return next_packet, received


"""
    Program input handling
"""


def parse_user_input(address, operation, file_name=None):
    if operation == "push":
        print(f"Attempting to upload [{file_name}]...")
        push(address, file_name)
        pass
    elif operation == "pull":
        print(f"Attempting to download [{file_name}]...")
        pull(address, file_name)
        pass
    else:
        print("Invalid operation request!\n")
        exit(-1)
        pass


def get_arg(param_index, default=None):
    """
        Gets a command line argument by index (note: index starts from 1)
        If the argument is not supplies, it tries to use a default value.

        If a default value isn't supplied, an error message is printed
        and terminates the program.
    """
    try:
        return sys.argv[param_index]
    except IndexError as e:
        if default:
            return default
        else:
            print(e)
            print(
                f"[FATAL] The command-line argument #[{param_index}] is missing")
            exit(-1)  # Program execution failed.


"""
    Main function
"""


def main():
    # Get arguments from cmd
    ip_address = get_arg(1, "127.0.0.1")
    operation = get_arg(2, "push")
    file_name = get_arg(3, "test.txt")
    # Print command line arguments
    print("*" * 50)
    print("[LOG] Printing command line arguments\n", ",".join(sys.argv))
    print(ip_address)
    print(operation)
    print(file_name)
    print("*" * 50)
    # Start a connection based on the user input
    parse_user_input(ip_address, operation, file_name)


if __name__ == "__main__":
    main()
