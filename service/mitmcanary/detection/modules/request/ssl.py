from mitmcanary.detection.request import RequestModule, RequestModuleManager
from mitmcanary.utilities.asn1tinydecoder import *

import struct
import os
import socket
import base64
import json


class SSLTools:
    def __init__(self):
        pass

    @staticmethod
    def _build_ssl_client_hello(hostname):
        buff = ""

        # Content Type
        buff += "\x16"
        # Version
        buff += "\x03\x01"
        # Length
        buff += struct.pack(">H", 183 + len(hostname))

        # Handshake Type
        buff += "\x01"
        # Length
        buff += "\x00" + struct.pack(">H", 179 + len(hostname))
        # Version
        buff += "\x03\x03"
        # Random Time
        buff += "\xe0\x94\x5e\xd4"  # Static time, probably should be random
        # Random Bytes
        # todo This will break on non-nix based systems...wont it
        buff += os.urandom(28)

        # Session ID Length
        buff += "\x00"
        # Cipher Suites Length
        buff += "\x00\x1a"
        # Cipher Suites
        buff += "\xc0\x2b\xc0\x2f\x00\x9e\xc0\x0a\xc0\x09\xc0\x13\xc0\x14\x00\x33\x00\x39\x00\x9c\x00\x2f\x00\x35\x00\x0a"

        # Compression Methods Length
        buff += "\x01"
        # Compression Methods
        buff += "\x00"

        # Extensions Length
        buff += struct.pack(">H", 112 + len(hostname))
        # Extension server name
        buff += "\x00\x00"
        # Length
        buff += struct.pack(">H", 5 + len(hostname))
        # Server Name list length
        buff += struct.pack(">H", 3 + len(hostname))
        # Server Name Type
        buff += "\x00"
        # Server Name length
        buff += struct.pack(">H", len(hostname))
        # Server Name
        buff += str(hostname)

        # renegotiation_info
        buff += "\xff\x01"
        # Length
        buff += "\x00\x01"
        # Renegotiation Info extension
        buff += "\x00"

        # elliptic curves
        buff += "\x00\x0a"
        # Length
        buff += "\x00\x08"
        # Length
        buff += "\x00\x06"
        # Curves
        buff += "\x00\x17\x00\x18\x00\x19"

        # ec_point_formats
        buff += "\x00\x0b"
        # Length
        buff += "\x00\x02"
        # Formats Length
        buff += "\x01"
        # Format Points
        buff += "\x00"

        # SessionTicket TLS
        buff += "\x00\x23"
        # Length
        buff += "\x00"
        # Data
        buff += "\x00"

        # next protocol negotiation
        buff += "\x33\x74\x00\x00"

        # Unknown 16
        buff += "\x00\x10\x00\x1d\x00\x1b\x08\x73\x70\x64\x79\x2f\x33\x2e\x31\x05\x68\x32\x2d\x31\x34\x02\x68\x32\x08\x68\x74\x74\x70\x2f\x31\x2e\x31"

        # Unknown 30032
        buff += "\x75\x50\x00\x00"

        # Status request
        buff += "\x00\x05\x00\x05\x01\x00\x00\x00\x00"

        # Unknown 18
        buff += "\x00\x12\x00\x00"

        # Signature Algorithms
        buff += "\x00\x0d\x00\x12\x00\x10\x04\x01\x05\x01\x02\x01\x04\x03\x05\x03\x02\x03\x04\x02\x02\x02"

        return buff

    @staticmethod
    def get_ssl_certificate_information_from_server(remote_ip, remote_port, s=None):
        if s is None:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.connect((remote_ip, remote_port))
        s.send(SSLTools._build_ssl_client_hello(remote_ip))
        data = ""

        while True:
            # Packet loop
            data += s.recv(1024)

            if data[0] != "\x16":
                print "Not a Handshake Packet..."
                raise

            packet_length = struct.unpack(">H", data[3:5])[0]

            while len(data) < packet_length + 5:
                data += s.recv(1024)

            record_data = data[5:5 + packet_length]
            data = data[5 + packet_length:]

            while len(record_data) != 0:
                message_length = struct.unpack(">i", "\x00" + record_data[1:4])[0]

                if record_data[0] != "\x0b":
                    # jump to next message in record
                    record_data = record_data[message_length + 4:]
                    continue

                record_data = record_data[:message_length + 4]

                certs = []
                index = 7

                while index < len(record_data):
                    certificate_length = struct.unpack('>i', '\x00' + record_data[index:index + 3])[0]
                    index += 3
                    certs.append(record_data[index:index + certificate_length])
                    index += certificate_length

                s.close()
                return ["-----BEGIN CERTIFICATE-----" + base64.b64encode(cert) + "-----END CERTIFICATE-----" for cert in
                        certs]

        s.close()
        return []


class SSLRequestModule(RequestModule):
    def get_name(self):
        return "SSL Request"

    def __init__(self):
        RequestModule.__init__(self)

    def make_request(self, request_arguments):
        host = str(request_arguments["remote_host"])
        port = int(request_arguments["remote_port"])
        chain = SSLTools.get_ssl_certificate_information_from_server(host, port)

        return {"ssl": {
            "chain": json.dumps(chain)
        }}


RequestModuleManager.i().add_module(SSLRequestModule())
