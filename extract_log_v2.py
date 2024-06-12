import win32evtlog
import win32evtlogutil
import datetime
import subprocess
from collections import defaultdict

log_file_path = 'c:\\login.log'
white_list_file='c:\\while_list'
black_list_file='c:\\black_list'

now = datetime.datetime.now()
two_hours_ago = now - datetime.timedelta(hours=144)

def load_lists():
    blacklist = set()
    whitelist=set()
    try:
        with open(black_list_file, 'r') as f:
            blacklist=set(f.read().splitlines())
        with open(white_list_file, 'r') as f:
            whitelist=set(f.read().splitlines())
    except FileNotFoundError:
        pass # if no list, create empty list
    return blacklist, whitelist

def update_list(list_set, list_path, is_block: bool):
    with open(list_path, 'w') as f:
        for ip in list_set:
            f.write(ip + '\n')
            update_fw_ip(ip, is_block)

def check_ip_and_update_lists(login_failures: dict):
    blacklist, whitelist = load_lists()

    for ip, failures in login_failures.items():
        if ip == '-' or ip == "127.0.0.1":
            continue
        if failures < 0 and ip not in blacklist:
            # login succeed, add to whitelist if not in blacklist
            whitelist.add(ip)
        elif failures >=8 and ip not in whitelist:
            blacklist.add(ip)
        else:
            # have failures less than 8, ignore for now
            pass
    update_list(blacklist, black_list_file, True)
    update_list(whitelist, white_list_file, False)

def update_fw_ip(ip: str, is_block: bool):
    # predefined rule name
    rule_name = f"PY_FW_BLOCK'_{ip}"

    # check rule existence
    result = subprocess.run(['netsh', 'advfirewall', 'firewall', 'show', 'rule', 'name', rule_name], capture_output=True, text=True)
    
    if result.returncode == 0:
        # exists rule
        if is_block:
            print(f"IP {ip} is already blocked by the firewall. no action needed")
        else:
            subprocess.run(['netsh', 'advfirewall', 'firewall', 'delete', 'rule', 'name', rule_name], check=True)
            print(f"Firewall rule to unblock {ip} has been deleted.")
        return
    else:
        # no existing rule, add block rule
        try:
            if is_block:
                # add block rule
                subprocess.run(['netsh', 'advfirewall', 'firewall', 'add', 'rule', 'name=' + rule_name, 
                                 'dir=in', 'action=block', 'protocol=TCP', 'remoteip=' + ip, 'enable=yes'], check=True)
                print(f"Firewall rule to block {ip} has been added.")
            else:
                print(f"No Firewall rule for allowed {ip}, no action needed.")
        except subprocess.CalledProcessError as e:
            print(f"Failed to update firewall rule for {ip}: {e}")

def extrac_login(start, end):
    hand = win32evtlog.OpenEventLog('localhost', 'Security')
    login_failures = {}
    try:
        total = win32evtlog.GetNumberOfEventLogRecords(hand)
        print (f'total {total} security logs')
        flags = win32evtlog.EVENTLOG_BACKWARDS_READ|win32evtlog.EVENTLOG_SEQUENTIAL_READ
        with open(log_file_path, 'w') as log_file:
            while True:
                events=win32evtlog.ReadEventLog(hand,flags,0)
                if events :
                    for event in events:
                        # print (f'event id : {event.EventID}')
                        if event.EventID == 4624 or event.EventID == 4625 :
                            # check time
                            data = event.StringInserts
                            # print (f' logon record ==== {str(event.TimeGenerated)} , {event.RecordNumber},  {event.EventID}')
                            # print (data)
                            event_time = datetime.datetime.strptime(str(event.TimeGenerated), "%Y-%m-%d %H:%M:%S")

                            if start <= event_time <= end:
                                # get ip, user, logontype, and status
                                ip_address = data[18]
                                user_name = data[5]
                                if event.EventID == 4624:
                                    logon_status = 'succeed'
                                    login_failures[ip_address] = -1
                                else:
                                    logon_status = 'failure'
                                    if ip_address in login_failures:
                                        print(f'{ip_address} login failed at {str(event.TimeGenerated)}, current failure count: {login_failures[ip_address]}')
                                        if login_failures[ip_address] > 0:
                                            login_failures[ip_address] += 1 # not to update if already login succeed: login_failure=-1
                                    else:
                                        login_failures[ip_address] = 1
                                # write
                                log_file.write(f'{event_time}, {ip_address}, {user_name}, {logon_status}\n')
                else:
                    break
    finally:
        win32evtlog.CloseEventLog(hand)
    print(f'login log of last two hours into {log_file_path}')
    return login_failures

if __name__ == '__main__':
    login_failures = extrac_login(two_hours_ago, now)
    print(login_failures)

    check_ip_and_update_lists(login_failures)
    print(f'updated ip and list')
