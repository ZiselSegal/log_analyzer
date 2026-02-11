from config import external_ips , large_file , sensetive_ports
import csv
from datetime import time

def log_reader():
    with open('network_traffic.log','r') as log:
        reader = csv.reader(log)
        return list(reader)

def get_external_ips():
    external_ips_list = [ip[1] for ip in log_reader() if not ip[1].startswith(external_ips[0]) and not ip[1].startswith(external_ips[1])]
    return external_ips_list

def filter_suspicions():
    suspicion_dict = get_suspicions()
    filtered_dict = {key : suspicion_dict[key] for key in suspicion_dict if len(suspicion_dict[key]) >= 2}
    return filtered_dict

def get_night_logs():
    night_logs = list(filter(lambda line : check_time_range(time(00,00,00),time(6,0,0),line[0].split()[1].split(':')[0]),log_reader()))
    return night_logs

def get_sensetive_ports():
    sensetive_ports = [port for port in log_reader() if port[3]  in sensetive_ports]
    return sensetive_ports

def get_large_logs():
    large_logs = [file for file in log_reader() if int(file[5]) > large_file]
    return large_logs

def tag_logs():
    tagged_logs = [line + ["LARGE"] if int(line[5]) > large_file else line + ['NORAML'] for line in log_reader()]
    return tagged_logs
    
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

def get_log_times():
    timestamps = list(map(lambda line : line[0].split()[1].split(':')[0],log_reader()))
    return timestamps

def convert_size_kb():
    converted_sizes = list(map(lambda line : int(line[5]) / 1024,log_reader()))
    return converted_sizes

def check_time_range(start,end,hour):
    start = start
    current = time(int((hour)),00,00)
    end =  end
    return start <= current <= end

def get_suspicions():
    suspicions_dict = {}
    external = get_external_ips()
    for line in log_reader():
        if line[1] in external:
            suspicions_dict.setdefault(line[1],set()).add('EXTERNAL_IP')
        if line[3] in sensetive_ports:
            suspicions_dict.setdefault(line[1],set()).add('SENSETIVE_PORT')
        if int(line[5]) > large_file:
            suspicions_dict.setdefault(line[1],set()).add('LARGE_PACKET')
        if check_time_range(time(00,00,00),time(6,0,0),line[0][11:13]):
            suspicions_dict.setdefault(line[1],set()).add('NIGHT ACTIVITY')
    for key in suspicions_dict.keys():
        suspicions_dict[key] = list(suspicions_dict[key])
    return suspicions_dict



def get_sensetive_ports_lines():
    sensetive_lines = list(filter(lambda line : line[3] in sensetive_ports,log_reader()))
    return sensetive_lines

def create_reviewer_dict():
    ext_ips = set(get_external_ips())
    reviewer_dict = {'EXTERNAL_IP' : lambda line : line[1] in ext_ips,
                     'SENSETIVE_PORT' : lambda line : line[3] in sensetive_ports,
                     'LARGE_PACKET' : lambda line : int(line[5]) > large_file,
                     'NIGHT ACTIVITY' : lambda line : check_time_range(time(00,00,00),time(6,0,0),line[0].split()[1].split(':')[0])}
    return reviewer_dict


def get_line_by_suspicion(line,reviewer_dict):
    line_suspicions = [key for key in reviewer_dict if reviewer_dict[key](line)]
    return line_suspicions

def get_all_suspicous_logs():
    all_lines = log_reader()
    rev_dict = create_reviewer_dict()
    # for line in log_reader():
    #     suspicions.append(get_line_by_suspicion(line,rev_dict))
    suspicions = map(lambda line : get_line_by_suspicion(line,rev_dict),all_lines)
    filtered = list(filter(lambda line : len(line) > 0,suspicions))
    return filtered
print(get_all_suspicous_logs())




    