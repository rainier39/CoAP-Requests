# https://github.com/rainier39/CoAP-Requests

import socket
import random

# Main function handling the requests.
def _rawCoAP(hostname, code: bytearray, payload="", port: int=5683, options: bytearray=""):
  if (hostname.startswith("coap://")):
    hostname = hostname[7:]

  server = socket.gethostbyname(hostname)

  conn = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
  conn.connect((server, port))

  ver_t_tkl = b"\x40"
  # We generate a pseudo-random messageID each time.
  messageID = random.randbytes(2)
  # Padding is only sent if there is a payload.
  if (len(payload) > 0):
    padding = b"\xff"
  else:
    padding = b""
  # If the payload is a regular string, turn it into bytes.
  if (type(payload) == str):
    payload = payload.encode()
  conn.send((ver_t_tkl + code + messageID + options + padding + payload))

  resp = conn.recv(4096)

  conn.close()
  
  return resp

# Wrapper function for performing GET requests.
def get(uri):
  if (uri.startswith("coap://")):
    uri = uri[7:]
  elif (uri.startswith("coaps://")):
    print("Unsupported protocol: coaps.")
    return
  # Break up the URI into the hostname and payload portion.
  if "/" in uri:
    hostname = uri[:uri.find("/")]
    payload = uri[uri.find("/")+1:]
  else:
    hostname = uri
    payload = ""
  # Use the provided port if there is one.
  if ":" in hostname:
    port = int(hostname[hostname.find(":")+1:])
    hostname = hostname[:hostname.find(":")]
  # Otherwise assume the default coap port as per the coap specification.
  else:
    port = 5683
  # If the payload is a regular string, turn it into bytes.
  if (type(payload) == str):
    payload = payload.encode()
  options = b""
  if (len(payload) > 0):
    if (len(payload) < 13):
      options = (int("b0", 16)^len(payload)).to_bytes()
    elif (len(payload) < 269):
      options = b"\xbd"
      options += (len(payload)-13).to_bytes()
    # Doesn't currently error out if the payload is larger than 16 bit int limit + 269. TODO
    else:
      options = b"\xbe"
      options += (len(payload)-269).to_bytes()
  if (options != ""):
    options=options+payload
  return _rawCoAP(hostname, b"\x01", "", port, options=options)

# Send a GET request to a public test server.
print(get("coap://coap.me/test"))
