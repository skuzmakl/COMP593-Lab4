"""
=================================================

 _____ ________  _________   _____  _____  _____ 
/  __ \  _  |  \/  || ___ \ |  ___||  _  ||____ |
| /  \/ | | | .  . || |_/ / |___ \ | |_| |    / /
| |   | | | | |\/| ||  __/      \ \\____ |    \ \
| \__/\ \_/ / |  | || |     /\__/ /.___/ /.___/ /
 \____/\___/\_|  |_/\_|     \____/ \____/ \____/ 
                                                 
=================================================

Assignment 4 - Exercise 1

Description:
 Processes a gateway log file then creates multiple csv files for destination port traffic, a csv file of invalid user login attempts, and a log file of specific source IP addresses

Usage:
 python COMP593_A4E1.py log_file

Parameters:
 log_file = file path of the log file
"""

from log_analysis import get_log_file_path_from_cmd_line, filter_log_by_regex
import pandas as pd
import re

def main():
    log_file = get_log_file_path_from_cmd_line(1)
    dpt_tally = tally_port_traffic(log_file)

    for dpt, count in dpt_tally.items():
        if count > 100:
            generate_port_traffic_report(log_file, dpt)

    generate_invalid_user_report(log_file)
    generate_source_ip_log(log_file, '220.195.35.40')

def tally_port_traffic(log_file):
    dest_port_logs = filter_log_by_regex(log_file, 'DPT=(.+?) ')[1]
    
    dpt_tally = {}
    for dpt_tuple in dest_port_logs:
        dpt_num = dpt_tuple[0]
        dpt_tally[dpt_num] = dpt_tally.get(dpt_num, 0) + 1

    return dpt_tally

def generate_port_traffic_report(log_file, port_number):
    regex = r"^(.{6}) (.{8}).*SRC=(.+?) DST=(.+?) .*SPT=(.+?) " + f"DPT=({port_number}) "
    captured_data = filter_log_by_regex(log_file, regex)[1]

    report_df = pd.DataFrame(captured_data)
    report_header = ('Date', 'Time', 'Source IP Address', 'Destination IP Address', 'Source Port', 'Destination Port')
    report_df.to_csv(f'destination_port_{port_number}_report.csv', index=False, header=report_header)

def generate_invalid_user_report(log_file):
    regex = r"^(.{6}) (.{8}).*Invalid user (.+?) from (.+)"
    captured_data = filter_log_by_regex(log_file, regex)[1]

    report_df = pd.DataFrame(captured_data)
    report_header = ('Date', 'Time', 'Username', 'IP address')
    report_df.to_csv(f'invalid_users.csv', index=False, header=report_header)

def generate_source_ip_log(log_file, ip_address):
    regex = r"SRC=" + f"{ip_address}"
    ip_log_data = filter_log_by_regex(log_file, regex)[0]

    log_df = pd.DataFrame(ip_log_data)
    address = re.sub(r'\.', '_', ip_address)
    log_df.to_csv(f'source_ip_{address}.log', index=False, header=False)

if __name__ == '__main__':
    main()