from scapy.all import *
from collections import Counter
import numpy as np
import pandas as pd
import datetime
#this is a test
from scapy.layers.dns import DNSQR, DNSRR
#amother test
#thrid test

# Define the length of each time window (in seconds)
window_length = 3600  # 1 hour

# Define the total observation time (in seconds)
total_time = 2 * 7 * 24 * 3600  # 2 weeks

# Define the start date and time for the observation period
start_date = "2019-08-01 00:00:00"
start_timestamp = datetime.datetime.strptime(start_date, "%Y-%m-%d %H:%M:%S").timestamp()

# Define the end date and time for the observation period
end_date = "2019-08-15 23:59:59"
end_timestamp = datetime.datetime.strptime(end_date, "%Y-%m-%d %H:%M:%S").timestamp()

# Read the .pcap file for the device
pcap_file = "device24_Train.pcap"

# Read the .pcap file
packets = rdpcap(pcap_file)

# Extract the DNS queries and their timestamps
dns_queries = []
dns_answers = []
for packet in packets:
    if packet.haslayer(DNSQR):
        dns_queries.append((packet[DNSQR].qname.decode("utf-8"), packet.time))
    if packet.haslayer(DNSRR):
        dns_answers.append((packet[DNSRR].rrname.decode("utf-8"), packet.time))

# Create a list of time windows using the start and end timestamps
time_windows = np.arange(start_timestamp, end_timestamp + window_length, window_length)

# For each time window, check if a domain was queried or answered at least once.
# lists is a tuple where the first element (q[0]) is the domain name and the second element (q[1]) is the timestamp
queried_domains = []
for i in range(len(time_windows) - 1):
    window_start = time_windows[i]
    window_end = time_windows[i+1]
    domains_in_window = [q[0] for q in dns_queries + dns_answers if window_start <= q[1] < window_end]
    queried_domains.extend(list(set(domains_in_window)))

# Count the number of time windows in which each domain was queried or answered
domain_counts = Counter(queried_domains)

# Compute the probabilities
total_windows = len(time_windows) - 1
probabilities = {domain: count / total_windows for domain, count in domain_counts.items()}

# Convert the probabilities to a DataFrame and save it to a CSV file
df_prob = pd.DataFrame(list(probabilities.items()), columns=['Domain', 'Probability'])
df_prob.to_csv("domain_probabilities.csv", index=False)


