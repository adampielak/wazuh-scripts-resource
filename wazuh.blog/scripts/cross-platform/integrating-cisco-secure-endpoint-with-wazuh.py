<!-- Source: https://wazuh.com/blog/integrating-cisco-secure-endpoint/ | Article: Integrating Cisco Secure Endpoint with Wazuh -->
#!/var/ossec/framework/python/bin/python3

import pika
import ssl
from socket import socket, AF_UNIX, SOCK_DGRAM

user_name = "<STREAM_USERNAME>"
queue_name = "<STREAM_QUEUE_NAME>"
password = "<STREAM_PASSWORD>"
host = "<STREAM_HOSTNAME>"
port = "<STREAM_PORT>"

socket_addr = '/var/ossec/queue/sockets/queue'

def send_event(msg):
    string = '1:ciscoendpoint:{"ciscoendpoint":' + msg.decode('utf-8') + '}'
    sock = socket(AF_UNIX, SOCK_DGRAM)
    sock.connect(socket_addr)
    sock.send(string.encode())
    sock.close()
    return True

def callback(channel, method, properties, body):
    try:
        send_event(body)
        channel.basic_ack(delivery_tag=method.delivery_tag)
        print("Cisco Secure Endpoint log sent to Wazuh")
    except Exception as e:
        print("Failed to send Cisco Secure Endpoint log to Wazuh")

amqp_url = f"amqps://{user_name}:{password}@{host}:{port}"

context = ssl.SSLContext(ssl.PROTOCOL_TLSv1_2)
amqp_ssl = pika.SSLOptions(context)

params = pika.URLParameters(amqp_url)
params.ssl_options = amqp_ssl

connection = pika.BlockingConnection(params)
channel = connection.channel()

channel.basic_consume(
    queue_name,
    callback,
    auto_ack = False
)

channel.start_consuming()