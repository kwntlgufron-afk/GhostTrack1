from scapy.all import sniff, IP, TCP
import requests

def get_ip_from_phone_number(phone_number):
 # Replace 'fdbc27cad87092' with your actual API key from a geolocation service
 api_key = 'fdbc27cad87092'
 url = f'http://ipinfo.io/{phone_number}/json?token={api_key}'

 response = requests.get(url)

 if response.status_code == 200:
 data = response.json()
 return data.get('ip', None)
 else:
 return Nonedef packet_callback(packet):
 if IP in packet:
 ip_src = packet[IP].src
 ip_dst = packet[IP].dst
 print(f"IP Source: {ip_src}, IP Destination: {ip_dst}")

 if TCP in packet:
 payload packet[TCP].payload.load
 print(f"Payload: {payload}")

def main():
 phone_number = input("Enter the phone number: ")
 print(f"Capturing network traffic for phone number: {phone_number}")

 # Start capturing packets
 sniff(filter="ip prn=packet_callback, store=0)

 # Get IP address from phone number using a geolocation service
 ip_address = get_ip_from_phone_number(phone_number)

 if ip_address:
 print(f"The IP address for phone number {phone_number} is {ip_address} else:
 print(f"No IP address found for phone number {phone_number}.")

if __name__ == "__main__":
 main()