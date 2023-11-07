from scapy.all import *
import datetime
import logging
from logging.handlers import RotatingFileHandler
import smtplib

# Define a list of blacklisted IP addresses
blacklist = ['10.0.2.15', '5.6.7.8']

# Define a list of whitelisted IP addresses
whitelist = ['10.0.0.1', '192.168.0.1', '192.168.29.1','142.250.195.99']

# Set up logging
log_formatter = logging.Formatter('%(asctime)s - %(levelname)s - %(message)s')
log_file = 'network_intrusion_detection.log'
log_handler = RotatingFileHandler(log_file, mode='a', maxBytes=5*1024*1024, backupCount=2, encoding=None, delay=0)

logging.basicConfig(filename='int.log', level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
log = logging.getLogger()

log_handler.setFormatter(log_formatter)
log_handler.setLevel(logging.INFO)
log = logging.getLogger('root')
log.setLevel(logging.INFO)
log.addHandler(log_handler)

import logging

def send_alert_email(msg):
    smtp_server = 'smtp.gmail.com'
    smtp_port = 587
    smtp_username = '21pc01@psgtech.ac.in'
    smtp_password = 'fwxxvlcrxlovusqo'
    sender = '21pc01@psgtech.ac.in'
    recipient = 'abarnasathya@gmail.com'
    subject = 'Network Intrusion Detected'
    body = msg
    try:
        server = smtplib.SMTP(smtp_server, smtp_port)
        server.ehlo()
        server.starttls()
        server.login(smtp_username, smtp_password)
        message = f"Subject: {subject}\n\n{body}"
        server.sendmail(sender, recipient, message)
        server.quit()
        print("Email Sent")
    except Exception as e:
        print(f"An error occurred while sending the email: {e}")

# Define the function to detect network intrusions and block/blacklist IPs
def detect_intrusions(pkt):
    if IP in pkt:
        src_ip = pkt[IP].src
        dst_ip = pkt[IP].dst
        if pkt.haslayer(TCP):
            src_port = pkt[TCP].sport
            dst_port = pkt[TCP].dport
            flags = pkt[TCP].flags

            # Check if the source IP is in the blacklist
            if src_ip in blacklist:
                msg = f"BLACKLISTED IP {src_ip} detected from {dst_ip}"
                log.error(msg)
                #send_alert_email(msg)
                # Block the IP by sending a RST packet
                rst_pkt = IP(dst=src_ip, src=dst_ip) / TCP(dport=src_port, sport=dst_port, flags='R')
                send(rst_pkt, verbose=0)
            # Check if the source IP is in the whitelist
            elif src_ip in whitelist:
                msg = f"WHITELISTED IP {src_ip} detected from {dst_ip}"
                log.info(msg)
            # If the source IP is not blacklisted or whitelisted, check for intrusion attempts
            elif flags == 0x12:
                msg = f"SYN packet from {src_ip}:{src_port} to {dst_ip}:{dst_port}"
                log.warning(msg)
                #send_alert_email(msg)
            elif flags == 0x14:
                msg = f"RST packet from {src_ip}:{src_port} to {dst_ip}:{dst_port}"
                log.warning(msg)
                send_alert_email(msg)

# Read packets from a PCAP file
def read_pcap(pcap_file):
    packets = rdpcap(pcap_file)
    for pkt in packets:
        detect_intrusions(pkt)
# Specify the PCAP file to read
pcap_file = 'tcp.pcapng'
# Perform intrusion detection on the PCAP file
read_pcap(pcap_file)