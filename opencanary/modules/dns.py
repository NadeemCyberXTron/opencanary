from twisted.application import internet
from twisted.internet import protocol
from opencanary.modules import CanaryService

class DNSProtocol(protocol.DatagramProtocol):
    def datagramReceived(self, data, addr):
        # 1. Log the attempt (Keep your existing logic)
        try:
            query = "".join([chr(b) if 32 < b < 127 else " " for b in data])
            domain = " ".join(query.split())
            
            logdata = {'path': domain, 'message': 'DNS Query detected'}
            # Fake peer object for the logger
            self.transport.getPeer = lambda: type('Peer', (object,), {'host': addr[0], 'port': addr[1]})
            self.factory.canaryservice.log(logdata, transport=self.transport)
            
            # 2. SEND RESPONSE
            # We take the first 2 bytes (Transaction ID) and 
            # add a standard "Server Failure" (RCODE 2) response header.
            if len(data) > 2:
                # \x81\x82 is a standard flags field for a response with an error
                response = data[:2] + b"\x81\x82\x00\x01\x00\x00\x00\x00\x00\x00"
                self.transport.write(response, addr)

        except Exception as e:
            pass
class CanaryDNS(CanaryService):
    NAME = "dns"

    def __init__(self, config=None, logger=None):
        CanaryService.__init__(self, config=config, logger=logger)
        self.port = int(config.getVal("dns.port", default=53))
        self.logtype = logger.LOG_DNS_QUERY
        self.listen_addr = config.getVal("device.listen_addr", default="")

    def getService(self):
        # UDP uses UDPServer and doesn't require a Factory, 
        # but we attach ourselves to the protocol so it can access .log()
        f = protocol.AbstractDatagramProtocol()
        f.canaryservice = self
        
        # We use the DNSProtocol class we defined above
        proto = DNSProtocol()
        proto.factory = f
        
        return internet.UDPServer(self.port, proto, interface=self.listen_addr)