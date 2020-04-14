import json
from urllib.request import urlopen
import mapdata_pb2
import socket

# remailer first. Location logger
def location_logger():
   port = 12345
   try:
       s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
       print("Socket successfully created")
   except socket.error as err:
       print("socket creation failed with error %s" % (err))
   
   #try:
   s.connect(('52.37.103.34', port))
   
   #Getting public ip info
   info = urlopen('http://ipinfo.io/json')
   data = json.load(info)
   location = data['loc'].split(',')
   public_ip = data['ip']
   latitude = float(location[0])
   longitude = float(location[1])
   
   wrapper_mssg = mapdata_pb2.wrapper()
   wrapper_mssg.mapx.ip = public_ip
   wrapper_mssg.mapx.latitude = latitude
   wrapper_mssg.mapx.longitude = longitude
   s.sendall(wrapper_mssg.SerializeToString())
   s.close()

# email forward
def sending_to_logger(ip_addr):
   port = 12345
   try:
       s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
       print("Socket successfully created")
   except socket.error as err:
       print("socket creation failed with error %s" % (err))
   # try:
   s.connect(('52.37.103.34', port))
   info = urlopen('http://ipinfo.io/json')
   data = json.load(info)
   public_ip = data['ip']
   sending_to = ip_addr # next hop address
   wrapper_mssg = mapdata_pb2.wrapper()
   wrapper_mssg.fromtox.from_ip = public_ip
   wrapper_mssg.fromtox.to_ip = sending_to
   s.sendall(wrapper_mssg.SerializeToString())
   s.close()