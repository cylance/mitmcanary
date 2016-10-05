from mitmcanary.detection.request import RequestModule, RequestModuleManager

import socket
import struct
import sys
import time
from datetime import datetime


class DNSARequestModule(RequestModule):
    def get_name(self):
        return "DNS A Request"

    def __init__(self):
        RequestModule.__init__(self)

    def make_request(self, request_arguments):
        domain = str(request_arguments["domain"])
        try:
            result = socket.gethostbyname(domain)
        except:
            result = None

        return {"ip": {"address": result}}


class MDNSRequestModule(RequestModule):
    def get_name(self):
        return "MDNS A Request"

    def __init__(self):
        RequestModule.__init__(self)

    def get_mdns_sock(self):
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        if sys.platform == 'darwin':
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEPORT, 1)
        sock.bind(('', 5353))

        mreq = struct.pack("4sl", socket.inet_aton('224.0.0.251'), socket.INADDR_ANY)
        sock.setsockopt(socket.IPPROTO_IP, socket.IP_ADD_MEMBERSHIP, mreq)

        return sock

    def make_request(self, request_arguments):
        original_domain = str(request_arguments["domain"])
        raw_domain_parts = original_domain.split(".")
        raw_domain = ""
        for domain in raw_domain_parts:
            raw_domain += chr(len(domain)) + domain

        sock = self.get_mdns_sock()

        sock.sendto('\x00\x00\x00\x00\x00\x01\x00\x00\x00\x00\x00\x00' + raw_domain + '\x00\x00\x01\x00\x01', ('224.0.0.251', 5353))
        start_time = datetime.utcnow()
        sock.setblocking(0)
        while (datetime.utcnow() - start_time).total_seconds() < 10:
            time.sleep(1)

            try:
                buf, remote = sock.recvfrom(8192)
            except socket.error:
                continue

            extracted_data = {}

            try:
                # Oh look, manual parsing
                extracted_data['transaction_id'] = struct.unpack(">H", buf[0:2])[0]
                extracted_data['flags'] = struct.unpack(">H", buf[2:4])[0]
                extracted_data['questions'] = struct.unpack(">H", buf[4:6])[0]
                answer_rr = struct.unpack(">H", buf[6:8])[0]
                extracted_data['answer_rr'] = answer_rr
                extracted_data['authority_rr'] = struct.unpack(">H", buf[8:10])[0]
                extracted_data['additional_rr'] = struct.unpack(">H", buf[10:12])[0]
                index = 12

                extracted_data['answers'] = []

                while answer_rr > 0 and index + 1 < len(buf):
                    domain = ""
                    if buf[index] == "\xc0":
                        orig_index = index
                        index = struct.unpack("B", buf[index + 1])[0]
                        while buf[index] != "\x00":
                            length = struct.unpack("B", buf[index])[0]
                            index += 1
                            domain += buf[index:index + length] + "."
                            index += length
                        index = orig_index + 2
                    else:
                        while buf[index] != "\x00":
                            length = struct.unpack("B", buf[index])[0]
                            index += 1
                            domain += buf[index:index + length] + "."
                            index += length
                    extracted_data['answers'] = domain
                    index += 1
                    answer_type = struct.unpack(">H", buf[index:index + 2])[0]
                    index += 2
                    answer_class = struct.unpack(">H", buf[index:index + 2])[0]
                    index += 2
                    answer_ttl = struct.unpack(">I", buf[index:index + 4])[0]
                    index += 4
                    answer_len = struct.unpack(">H", buf[index:index + 2])[0]
                    index += 2

                    ip = None
                    if answer_len == 4:
                        ip = ".".join([str(ord(i)) for i in buf[index:index + 4]])
                    index += answer_len

                    answer_rr -= 1

                    if domain == original_domain or domain == original_domain + ".":
                        sock.close()
                        return {"ip": {"address": ip}}

            except:
                #print [buf]
                #print extracted_data
                pass

        sock.close()
        return {"ip": {"address": None}}


RequestModuleManager.i().add_module(DNSARequestModule())
RequestModuleManager.i().add_module(MDNSRequestModule())
