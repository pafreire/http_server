import sys
import time
import socket
import base64
import hashlib
import struct
import _thread as thread


HOST = ''
DEFAULT_PORT = 80
BACKLOG = 5     # Maximum queued connections
TIMEOUT = 20     # Client connection timeout
BUFFER_SIZE = 1024
CRLF = '\r\n'
GUID = '258EAFA5-E914-47DA-95CA-C5AB0DC85B11'


class HTTPServer:
    """Provides a simple HTTPServer."""

    def __init__(self, port=DEFAULT_PORT):
        self.host = HOST or socket.gethostname().split('.')[0]
        self.port = port
        self.server_address = (self.host, self.port)
        self.socket = None

    def start(self):
        """Starts HTTP server."""
        print('Starting HTTP Server "{}"...'.format(self.host))
        try:
            self.socket = socket.socket(socket.AF_INET,
                                        socket.SOCK_STREAM)
            # Reuse local socket in TIME_WAIT
            self.socket.setsockopt(socket.SOL_SOCKET,
                                   socket.SO_REUSEADDR,
                                   1)
        except Exception as e:
            print('Error creating socket. \n{}'.format(e))
            sys.exit(1)
        print('Socket:\t OK')

        try:
            self.socket.bind(self.server_address)
        except Exception as e:
            print('Fail to bind. \n{}'.format(e))
            sys.exit(1)
        print('Bind:\t OK')

        self._listen()

    def stop(self):
        """Shutdown HTTP server."""
        print('\nShutdown HTTP server')
        self.socket.close()

    def _listen(self):
        """Opens socket for connections."""
        print('Listening on port (default={}): {}'.format(DEFAULT_PORT,
                                                          self.port))
        self.socket.listen(BACKLOG)
        print('Press CRTL-C to stop server.')

        while True:
            params = (connection, address) = self.socket.accept()
            thread.start_new_thread(self._client, params)

    def _client(self, conn, address):
        """Starts session with client."""
        print('connection from {}:{} '.format(address[0], address[1]))
        conn.settimeout(TIMEOUT)
        request = ''

        try:
            while True:
                data_input = conn.recv(BUFFER_SIZE).decode()
                request += data_input
                if data_input.endswith(CRLF):
                    break
            request_params = request.split()[:3]
            print('request from '
                  '{}:{} - {}'.format(address[0], address[1],
                                      ' '.join(request_params)))
            responses = self._request_handle(request)
        # TIMEOUT is reached, send 408 and close connection
        except socket.timeout:
            conn.sendall(self._response(408)[0])
            conn.close()
            thread.exit()

        for response in responses:
            conn.send(response)

        conn.close()
        thread.exit()

    def _response(self, code, only_header=False):
        """Returns response code statement."""
        responses = {
            200: 'HTTP/1.1 200 OK',
            400: 'HTTP/1.1 400 Bad Request',
            404: 'HTTP/1.1 404 Not Found',
            405: 'HTTP/1.1 405 Method Not Allowed',
            408: 'HTTP/1.1 408 Request Timeout',
            418: 'HTTP/1.1 418 I\'m a teapot',
            501: 'HTTP/1.1 501 Method Not Implemented'
        }
        response_code = responses.get(code,
                                      'HTTP/1.1 500 Internal Server Error')

        # Formats html body response
        response_html = response_code.split('HTTP/1.1')
        response_body = ['<html>', '<body bgcolor="white">',
                         '<center><h1>' + ' '.join(response_html).lstrip() +
                         '</h1></center>',
                         '<hr><center>Alfacinha HTTP Server</center>',
                         '</body>',
                         '</html>',
                         ' '
        ]

        # Formats header response
        gmt_now = time.strftime('%a, %d %b %Y %H:%M:%S %Z', time.gmtime())
        content_length = len(CRLF.join(response_body))
        response_header = [
            response_code,
            'Server: Alfacinha HTTP Server',
            'Date: {}'.format(gmt_now),
            'Content-Type: text/html',
            'Content-Length: {}'.format(content_length),
            'Connection: close',
            CRLF    # Separates headers from body
        ]

        if only_header:
            # Removes content-Length from header
            del response_header[4]
            response = (CRLF.join(response_header).encode(),)
        else:
            response = (
                        CRLF.join(response_header).encode(),
                        CRLF.join(response_body).encode()
            )
        return response

    def _response_ws(self, request):
        """Performs checks and reply as a websocket."""
        request_headers = request.replace(':', '').splitlines()

        if not request_headers:
            return self._response(400)

        headers = dict([line.split()
                        for line in request_headers
                        if line != '' and len(line.split()) == 2])

        if not ('Host' in headers or
                'Upgrade' in headers or
                'Connection' in headers or
                'Sec-WebSocket-Key' in headers or
                'Sec-WebSocket-Version' in headers):
            return self._response(400)

        if not (headers['Upgrade'] == 'websocket' or
                headers['Connection'] == 'Upgrade' or
                headers['Sec-WebSocket-Version'] == '13'):
            return self._response(400)

        key_client = headers['Sec-WebSocket-Key']
        key_concat = key_client.encode('ascii') + GUID.encode('ascii')
        key_server = base64.b64encode(
            hashlib.sha1(key_concat).digest()).decode('ascii')

        response_ws = [
            'HTTP/1.1 101 Switching Protocols',
            'Upgrade: websocket',
            'Connection: Upgrade',
            'Sec-WebSocket-Accept: {}'.format(key_server),
            CRLF
        ]

        payload_data = b'{ "status" : "success" }'
        if len(payload_data) > 125:
            print('Error: Payload > 125 Not Implemented')

        # See https://tools.ietf.org/html/rfc6455#section-5.2
        frame_header_1 = 0b10000001
        frame_header_2 = 0b0

        ws_frame = struct.pack('!BB', frame_header_1,
                               frame_header_2 | len(payload_data))

        response = (CRLF.join(response_ws).encode(),
                    ws_frame,
                    payload_data)
        return response

    def _request_handle(self, request):
        """Verifies request information and returns response."""
        methods = ('GET', 'POST', 'PUT', 'DELETE', 'HEAD')
        implemented_methods = ('GET', 'HEAD')
        sitepaths = ('/', '/ws')
        versions = ('HTTP/1.1', 'HTCPCP/1.0')

        if len(request.split()) < 3:
            return self._response(400)

        method = request.split()[0]
        uri = request.split()[1]
        version = request.split()[2]

        if method not in methods:
            return self._response(501)

        if method not in implemented_methods:
            return self._response(405)

        if uri not in sitepaths:
            return self._response(404)

        if version not in versions:
            return self._response(400)

        if version == 'HTCPCP/1.0':
            return self._response(418)

        if method == 'GET' and uri == '/' and version == 'HTTP/1.1':
            return self._response(200)

        if method == 'HEAD' and uri == '/' and version == 'HTTP/1.1':
            return self._response(200, only_header=True)

        if method == 'GET' and uri == '/ws' and version == 'HTTP/1.1':
            return self._response_ws(request)

        return self._response(400)


if __name__ == '__main__':

    try:
        server = HTTPServer(8080)
        server.start()
    except KeyboardInterrupt:
        server.stop()
