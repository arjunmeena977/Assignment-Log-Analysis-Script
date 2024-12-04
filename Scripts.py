import re
import csv
from collections import Counter, defaultdict
from datetime import datetime

# Configuration
LOG_FILE = "sample1.log" 
OUTPUT_FILE = "log_analysis_results.csv"  
FAILED_LOGIN_THRESHOLD = 1  

# Function to parse the log file
def ParseLog(file_path):
    IpAddr = re.compile(r'\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b')  
    endptAddr = re.compile(r'\"(?:GET|POST|PUT|DELETE) (.+?) HTTP')  
    status_code = re.compile(r'\s(\d{3})\s') 
    faild_ip_addr = re.compile(r'Invalid credentials') 

    ip_requests = Counter()
    hit_endpoints = Counter()  
    failed_logins = defaultdict(int)  

    with open(file_path, 'r') as log_file:
        for line in log_file:
            # Extract IP address
            ip_match = IpAddr.search(line)
            if ip_match:
                ip = ip_match.group()
                ip_requests[ip] += 1

            # Extract endpoint
            endpoint_match = endptAddr.search(line)
            if endpoint_match:
                endpoint = endpoint_match.group(1)
                hit_endpoints[endpoint] += 1

            # Detect failed logins (HTTP status `401`)
            status_match = status_code.search(line)  
            if status_match:
                status = status_match.group(1)  
                if status == "401" or faild_ip_addr.search(line): 
                    if ip_match:
                        failed_logins[ip] += 1

    return ip_requests, hit_endpoints, failed_logins


# Function to save results to CSV
def save_into_csv(ip_requests, hit_endpoints, failed_logins, output_file):
    with open(output_file, 'w', newline='') as csv_file:
        writer = csv.writer(csv_file)

        # Requests Per IP
        writer.writerow(["Requests Per IP"])
        writer.writerow(["IP Address", "Request Count"])
        for ip, count in ip_requests.items():
            writer.writerow([ip, count])

        writer.writerow([])  

       
        writer.writerow(["Most Frequently Accessed Endpoint"])
        if hit_endpoints:
            most_accessed = hit_endpoints.most_common(1)[0]
            writer.writerow(["Endpoint", "Access Count"])
            writer.writerow([most_accessed[0], most_accessed[1]])

        writer.writerow([])  

        # Suspicious Activity
        writer.writerow(["Suspicious Activity Detected"])
        writer.writerow(["IP Address", "Failed Login Count"])
        for ip, count in failed_logins.items():
            if count > FAILED_LOGIN_THRESHOLD:
                writer.writerow([ip, count])

# Main function
def main():
    print("Parsing log file...")
    ip_requests, hit_endpoints, failed_logins = ParseLog(LOG_FILE)

    # Console Output
    print("\nRequests per IP:")
    for ip, count in ip_requests.items():
        print(f"{ip:20} {count}")

    print("\nMost Frequently Accessed Endpoint:")
    if hit_endpoints:
        most_accessed = hit_endpoints.most_common(1)[0]
        print(f"{most_accessed[0]}\t (Accessed {most_accessed[1]} times)")

    print("\nSuspicious Activity Detected:")
    print(f"{'IP Address':<20} {'Failed Login Attempts'}")

    for ip, count in failed_logins.items():
        if count > FAILED_LOGIN_THRESHOLD:
            print(f"{ip:<20} {count}")

    # Save Results to CSV
    print("\nSaving results to CSV...")
    save_into_csv(ip_requests, hit_endpoints, failed_logins, OUTPUT_FILE)
    print(f"Results saved to {OUTPUT_FILE}")

if __name__ == "__main__":
    main()
