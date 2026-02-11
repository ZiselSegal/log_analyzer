from reader import log_reader
from config import external_ips,large_file,sensetive_ports

def get_external_ips():
    external_ips_list = [ip[1] for ip in log_reader() if not ip[1].startswith(external_ips[0]) and not ip[1].startswith(external_ips[1])]
    return external_ips_list

def get_sensetive_ports():
    sensetive_ports = [port for port in log_reader() if port[3]  in sensetive_ports]
    return sensetive_ports

def get_large_logs():
    large_logs = [file for file in log_reader() if int(file[5]) > large_file]
    return large_logs

def tag_logs():
    tagged_logs = [line + ["LARGE"] if int(line[5]) > large_file else line + ['NORAML'] for line in log_reader()]
    return tagged_logs