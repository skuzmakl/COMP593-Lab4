from log_analysis import get_log_file_path_from_cmd_line, filter_log_by_regex
import pandas as pd

def main():
    log_file = get_log_file_path_from_cmd_line(1)
    #records = filter_log_by_regex(log_file, 'SRC=(.*?) DST=(.*?) LEN=(.*?) ', print_summary=True, print_records=True)
    dpt_tally = tally_port_traffic(log_file)

    for dpt, count in dpt_tally.items():
        if count > 100:
            generate_port_traffic_report(log_file, dpt)

    pass

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

# TODO: Step 11
def generate_invalid_user_report(log_file):
    return

# TODO: Step 12
def generate_source_ip_log(log_file, ip_address):

    #captured_data = filter_log_by_regex(log_file, regex)[0]

    return

if __name__ == '__main__':
    main()