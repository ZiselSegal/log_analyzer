from config import large_file,sensetive_ports,external_ips

def get_all_logs():
    with open('network_traffic.log','r') as f:
        for line in f:
            line = line.strip('\n').split(',')
            yield line

def filter_suspicions(logs_generator):
    for line in logs_generator:
        if line[1] in external_ips or line[3] in sensetive_ports or int(line[5]) > large_file or 00 < int(line[0][11:13]) < 6:
            yield line
        continue

def suspicion_details(suspicious_filter):
    for line in suspicious_filter:
        flag = False
        suspicions_list = []
        if line[1] in external_ips:
            suspicions_list.append('EXTERNAL_IP')
            flag = True
        if line[3] in sensetive_ports:
            suspicions_list.append('SENSETIVE_PORT')
            flag = True
        if int(line[5]) > large_file:
            suspicions_list.append('LARGE_PACKET')
            flag = True
        if 00 < int(line[0][11:13]) < 6:
            suspicions_list.append('NIGHT_ACTIVITY')
            flag = True
        if flag == True:
            yield line,suspicions_list
        else:
            continue

def sum_suspicious_logs(filter_function):
    num = sum(1 for line in filter_function)
    return num

logs = get_all_logs()
filtered = filter_suspicions(logs)
detailed = suspicion_details(filtered)
sum = sum_suspicious_logs(detailed)
print(f'total suspicions: {sum}')



