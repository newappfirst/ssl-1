import socket
import ssl
import threading
def run_server(certfile, keyfile, port):
    bindsock = socket.socket()
    bindsock.bind(('',port))
    bindsock.listen(1)


    sock, source = bindsock.accept()
    sslsock = ssl.wrap_socket(sock, keyfile = keyfile, certfile = certfile, server_side = True, ssl_version = ssl.PROTOCOL_SSLv23)
    #TODO: any recv we may or may not want
    #sslsock.recv()
    sslsock.close()
    bindsock.close()
    sock.close()
class ServerThread(threading.Thread):
    def __init__(self, certfile, keyfile, port, event):
        threading.Thread.__init__(self)
        self.certfile = certfile
        self.keyfile = keyfile
        self.port = port
        self.event = event
        self.bound = False
    def run(self):
        try :
            bindsock = socket.socket()
            bindsock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            bindsock.bind(('',self.port))
            bindsock.listen(1)
            self.bound = True
            self.bindsock = bindsock
        except:
            # Signal we are done (the caller needs to check we bound correctly!
            self.event.set()
            return
        self.event.set()
        #Don't really care what happens from here out, if it fails it fails
        try:
            sock, source = bindsock.accept()
            self.sock = sock
            sslsock = ssl.wrap_socket(sock, keyfile = self.keyfile, certfile = self.certfile, server_side = True, ssl_version = ssl.PROTOCOL_SSLv23)
            self.sslsock = sslsock
            #TODO: any recv we may or may not want
            #sslsock.recv()
            sslsock.close()
            bindsock.close()
            sock.close()
        except:
            pass
    def close(self):
        try:
            self.bindsock.close()
        except:
            pass
        try:
            self.sock.close()
        except:
            pass
        try:
            self.sslsock.close()
        except:
            pass


if __name__ == "__main__":
    import sys
    if len(sys.argv) < 4:
        print("usage: %s certfile keyfile port" % sys.argv[0])
        sys.exit()
    run_server(sys.argv[1], sys.argv[2], int(sys.argv[3]))
