from reader import log_reader
from config import external_ips,large_file,sensetive_ports
from datetime import time
from aanalyzer import check_time_range

def get_sensetive_ports():
    sensetive_ports = [port for port in log_reader() if port[3]  in sensetive_ports]
    return sensetive_ports

def get_large_logs():
    large_logs = [file for file in log_reader() if int(file[5]) > large_file]
    return large_logs

def tag_logs():
    tagged_logs = [line + ["LARGE"] if int(line[5]) > large_file else line + ['NORAML'] for line in log_reader()]
    return tagged_logs

def get_sensetive_ports_lines():
    sensetive_lines = list(filter(lambda line : line[3] in sensetive_ports,log_reader()))
    return sensetive_lines

def create_reviewer_dict():
    reviewer_dict = {'EXTERNAL_IP' : lambda line : line not in external_ips,
                     'SENSETIVE_PORT' : lambda line : line in sensetive_ports,
                     'LARGE_PACKET' : lambda line : int(line) > large_file,
                     'NIGHT ACTIVITY' : lambda line : check_time_range(time(00,00,00),time(6,0,0),line[0].split()[1].split(':')[0])}
    return reviewer_dict
for k in create_reviewer_dict():
    print(k)


# def get_line_by_suspicion(line_num,reviewer_dict):
#         [dict for dict in reviewer_dict if filter(dict[])]

