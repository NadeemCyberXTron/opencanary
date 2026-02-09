import base64
from twisted.internet.protocol import Factory
from twisted.application import internet
from opencanary.modules import CanaryService, CanaryProtocol

class AlertAuthSMTPProtocol(CanaryProtocol):
    def __init__(self):
        self.state = "COMMAND"
        self.username = None

    def connectionMade(self):
        # Optional: Log connection like Telnet's log_tcp_connection
        if self.factory.canaryservice.config.getVal("smtp.log_tcp_connection", default=True):
            logtype = self.factory.canaryservice.logger.LOG_SMTP_CONN
            self.factory.canaryservice.log({}, transport=self.transport, logtype=logtype)
            
        self.transport.write(b"220 mail.corporate-server.com ESMTP Postfix\r\n")

    def dataReceived(self, data):
        line = data.decode('utf-8', errors='ignore').strip()
        cmd = line.upper()

        if self.state == "COMMAND":
            if cmd.startswith("AUTH LOGIN"):
                self.state = "USER"
                self.transport.write(b"334 VXNlcm5hbWU6\r\n") # "Username:"
            elif cmd.startswith("HELO") or cmd.startswith("EHLO"):
                self.transport.write(b"250-mail.corporate-server.com\r\n250 AUTH LOGIN\r\n")
            elif cmd.startswith("QUIT"):
                self.transport.loseConnection()
            else:
                self.transport.write(b"250 OK\r\n")

        elif self.state == "USER":
            try:
                self.username = base64.b64decode(line).decode('utf-8')
                self.state = "PASS"
                self.transport.write(b"334 UGFzc3dvcmQ6\r\n") # "Password:"
            except Exception:
                self.state = "COMMAND"
                self.transport.write(b"501 Invalid Base64\r\n")

        elif self.state == "PASS":
            try:
                password = base64.b64decode(line).decode('utf-8')
                
                # Use LOWERCASE keys to match your config file exactly
                logdata = {
                    "username": self.username, 
                    "password": password
                }
                
                self.factory.canaryservice.log(logdata, transport=self.transport)
            except Exception as e:
                pass            
            self.transport.write(b"535 5.7.8 Authentication failed\r\n")
            self.state = "COMMAND"

class CanarySMTP(CanaryService):
    NAME = "smtp"

    def __init__(self, config=None, logger=None):
        CanaryService.__init__(self, config=config, logger=logger)
        self.port = int(config.getVal("smtp.port", default=25))
        self.logtype = logger.LOG_SMTP_LOGIN
        self.listen_addr = config.getVal("device.listen_addr", default="")
        self.creds = config.getVal("smtp.honeycreds", default=[])
    def getService(self):
        # Following the Telnet factory pattern
        f = Factory()
        f.canaryservice = self
        f.protocol = AlertAuthSMTPProtocol
        return internet.TCPServer(self.port, f, interface=self.listen_addr)