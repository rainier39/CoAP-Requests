# https://github.com/rainier39/CoAP-Requests

import socket

# Default port for COAP.
PORT = 5683

# Main function handling the requests.
def _rawCoAP(hostname: str, code: bytearray, payload: str):
  if (hostname.startswith("coap://")):
    hostname = hostname[7:]

  server = socket.gethostbyname(hostname)

  conn = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
  conn.connect((server, PORT))

  ver_t_tkl = b"\x40"
  messageID = b"\x00\x00"
  # Padding is only sent if there is a payload.
  if (len(payload) > 0):
    padding = b"\xff"
  else:
    padding = b""
  conn.send((ver_t_tkl + code + messageID + padding + payload.encode()))

  resp = conn.recv(4096)

  conn.close()
  
  return resp

# Wrapper function for performing GET requests.
def get(hostname: str, payload: str=""):
  return _rawCoAP(hostname, b"\x01", payload)

# Send a GET request to a public test server.
print(get("coap://coap.me"))
