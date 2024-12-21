from scapy.all import *

# Constants for TTL and suspicious IPs
DEFAULT_TTL_MIN = 30
DEFAULT_TTL_MAX = 86400
query_id = {}  # Tracks DNS query IDs
SUSPICIOUS_IPS = ["66.66.66.66", "12.34.56.78"]  # List of suspicious IPs


def filter_dns(packet):
    """ Filters packets to only pass DNS packets."""
    return DNS in packet


def dns_sniffer():
    """ Starts sniffing for DNS packets. """
    print("Sniffing for DNS packets...")
    sniff(lfilter=filter_dns, prn=detect_dns_poisoning)


def poisoning_detected(id, reason):
    """ Logs detected DNS poisoning and removes the query ID. """
    if id in query_id:
        del query_id[id]
    print(f"DNS packet {id} suspicious: {reason}")


def detect_dns_poisoning(packet):
    """ Checks DNS packet for signs of poisoning. """
    if DNS in packet:
        qr = packet[DNS].qr #The value is either 0, a query or 1, a response.
        id = packet[DNS].id

        if qr == 0:
            query_id[id] = 0  # Track DNS query

        elif qr == 1 and id in query_id:
            query_id[id] += 1

            if query_id[id] > 1:
                #In this case there are multiple dns responses.
                poisoning_detected(id, "multiple answers")

            elif packet.haslayer(DNSRR):
                for dnsrr in packet[DNS].an:
                    ip = dnsrr.rdata
                    ttl = packet[IP].ttl

                    if ttl < DEFAULT_TTL_MIN or ttl > DEFAULT_TTL_MAX:
                        #In this case the ttl is suspicious
                        poisoning_detected(id, f"suspicious TTL: {ttl}")

                    if ip in SUSPICIOUS_IPS:
                        poisoning_detected(id, f"suspicious IP: {ip}")

if __name__ == "__main__":
    """ Run the DNS sniffer."""
    dns_sniffer()
