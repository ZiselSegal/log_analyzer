from datetime import time
from reader import log_reader
from checks import get_external_ips
from config import sensetive_ports,large_file

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

def filter_suspicions():
    suspicion_dict = get_suspicions()
    filtered_dict = {key : suspicion_dict[key] for key in suspicion_dict if len(suspicion_dict[key]) >= 2}
    return filtered_dict

