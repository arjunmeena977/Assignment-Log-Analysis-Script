from flask import Flask, request
import datetime

app = Flask(__name__)
LOG_FILE = "sample.log"

def log_request(ip_address, method, endpoint, protocol="HTTP/1.1", status_code=200, size=512, message="Request logged"):
    """
    Logs a request to the sample.log file.
    """
    timestamp = datetime.datetime.utcnow().strftime("%d/%b/%Y:%H:%M:%S +0000")
    log_entry = f'{ip_address} - - [{timestamp}] "{method} {endpoint} {protocol}" {status_code} {size} "{message}"\n'
    with open(LOG_FILE, "a") as file:
        file.write(log_entry)
    print(f"Logged request from IP: {ip_address}")

@app.route("/", methods=["GET", "POST"])
def index():
    
    client_ip = request.remote_addr
   
    method = request.method
    endpoint = request.path
    # Log the request
    log_request(client_ip, method, endpoint)
    return f"Request from {client_ip} logged!", 200

if __name__ == "__main__":
   
    app.run(host="0.0.0.0", port=5000)
