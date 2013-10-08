import socket
import ssl
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

if __name__ == "__main__":
    import sys
    if len(sys.argv) < 4:
        print("usage: %s certfile keyfile port" % sys.argv[0])
        sys.exit()
    run_server(sys.argv[1], sys.argv[2], int(sys.argv[3]))
