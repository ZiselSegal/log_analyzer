from config import external_ips , large_file , sensetive_ports
import csv

def log_reader():
    with open('network_traffic.log','r') as log:
        reader = csv.reader(log)
        return list(reader)
    
def count_requests():
    requests_dict = {}
    for line in log_reader():
        if line[1] in requests_dict:
            requests_dict[line[1]] += 1
        else:
            requests_dict[line[1]] = 1
    return requests_dict

def get_protocol_info():
    prot_info = {line[3] : line[4] for line in log_reader()}
    return prot_info


    