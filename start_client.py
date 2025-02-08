import subprocess, csv, os, logging, time, psutil, re
from concurrent.futures import ThreadPoolExecutor, as_completed
from threading import Thread, Lock
from datetime import datetime

logging.basicConfig(level=logging.DEBUG, format="%(asctime)s [%(levelname)s] %(message)s", handlers=[logging.StreamHandler()])

CURL_COMMAND_TEMPLATE = ["curl", "--tlsv1.3", "--curves", "x25519_mlkem512", "-k", "-w",
"Connect Time: %{time_connect}, TLS Handshake: %{time_appconnect}, Total Time: %{time_total}, %{http_code}\n","-s", "https://nginx_pq:4433"]

NUM_REQUESTS, OUTPUT_FILE, MONITOR_FILE, TRACE_LOG_DIR = 500, "/app/output/request_client.csv", "/app/output/system_client.csv", "/app/logs/"
os.makedirs(TRACE_LOG_DIR, exist_ok=True)

active_requests, active_requests_lock, global_stats = 0, Lock(), {"cpu_usage": [], "memory_usage": []}

def monitor_system():
    """Monitora CPU, memoria e connessioni attive."""
    with open(MONITOR_FILE, "w", newline="", encoding="utf-8") as f:
        writer = csv.writer(f); writer.writerow(["Timestamp", "CPU_Usage(%)", "Memory_Usage(MB)", "Active_TLS"])
        stable_counter = 0
        while True:
            with active_requests_lock: tls = active_requests
            writer.writerow([datetime.now().strftime("%Y-%m-%d %H:%M:%S.%f"), psutil.cpu_percent(), psutil.virtual_memory().used / (1024 ** 2), tls])
            if tls == 0: stable_counter += 1
            if stable_counter >= 5: break
            time.sleep(0.01)

def execute_request(req_num):
    """Esegue una richiesta HTTPS con `curl`, verifica HTTP 200 e analizza il file di trace generato."""
    global active_requests
    with active_requests_lock: active_requests += 1  
    trace_file = f"{TRACE_LOG_DIR}trace_{req_num}.log" 
    kem, sig_alg, cert_size = "Unknown", "Unknown", 0

    try:
        start = time.time()
        process = subprocess.Popen(CURL_COMMAND_TEMPLATE + ["--trace", trace_file, "-o", "/dev/null"], stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        elapsed_time = time.time() - start
        stdout, stderr = process.communicate()
        bytes_sent = bytes_received = 0
        previous_line = ""
        if os.path.exists(trace_file):
            with open(trace_file, "r", encoding="utf-8") as f:
                for line in f:
                    m_sent = re.search(r"(=> Send SSL data, (\d+) bytes|Send header, (\d+) bytes)", line)
                    m_recv = re.search(r"(<= Recv SSL data, (\d+) bytes|Recv header, (\d+) bytes|Recv data, (\d+) bytes)", line)
                    match_tls = re.search(r"SSL connection using TLSv1.3 / .* / (\S+) / (\S+)", line)
                    match_cert_size = re.search(r"<= Recv SSL data, (\d+) bytes", line)
                    bytes_sent += int(m_sent.group(2) or m_sent.group(3)) if m_sent else 0
                    bytes_received += int(m_recv.group(2) or m_recv.group(3) or m_recv.group(4)) if m_recv else 0
                    
                    if match_tls: kem, sig_alg = match_tls.group(1), match_tls.group(2)
                    
                    if "TLS handshake, Certificate (11):" in previous_line and match_cert_size:
                        cert_size = int(match_cert_size.group(1))
                    
                    previous_line = line

        try:
            metrics = stdout.strip().rsplit(", ", 1)
            http_status = metrics[-1].strip()
            metrics_dict = dict(item.split(": ") for item in metrics[0].split(", "))
            connect_time, handshake_time, total_time = float(metrics_dict["Connect Time"].replace("s", "")), float(metrics_dict["TLS Handshake"].replace("s", "")), float(metrics_dict["Total Time"].replace("s", ""))
            success_status = "Success" if http_status == "200" else "Failure"
        except:
            logging.error(f"Errore parsing metriche richiesta {req_num}")
            connect_time = handshake_time = total_time = None
            success_status = "Failure"

        logging.info(f"Richiesta {req_num}: {success_status} | Connessione={connect_time}s, Handshake={handshake_time}s, Totale={total_time}s, Tempo={elapsed_time}s, Inviati={bytes_sent}, Ricevuti={bytes_received}, HTTP={http_status}, KEM={kem}, Firma={sig_alg}, Cert_Size={cert_size}B")
        return [req_num, connect_time, handshake_time, total_time, elapsed_time, success_status, bytes_sent, bytes_received, kem, sig_alg, cert_size]

    except Exception as e:
        logging.error(f"Errore richiesta {req_num}: {e}")
        return [req_num, None, None, None, None, "Failure", 0, 0, kem, sig_alg, cert_size]

    finally:
        with active_requests_lock: active_requests -= 1  

with open(OUTPUT_FILE, "w", newline="", encoding="utf-8") as f:
    writer = csv.writer(f)
    writer.writerow(["Request_Number", "Connect_Time(s)", "TLS_Handshake(s)", "Total_Time(s)", "Elapsed_Time(s)", 
                     "Status", "Success_Count", "Bytes_Sent(B)", "Bytes_Received(B)", "KEM", "Signature", "Cert_Size(B)"])
    
    monitor_thread = Thread(target=monitor_system); monitor_thread.start()
    start_time = time.time()
    try:
        request_results = []  
        with ThreadPoolExecutor(max_workers=NUM_REQUESTS) as executor:
            futures = [executor.submit(execute_request, i + 1) for i in range(NUM_REQUESTS)]  
            for future in as_completed(futures):
                request_results.append(future.result()) 
    finally:
        monitor_thread.join()
        end_time = time.time()

    success_count = 0
    for result in request_results:
        request_number = result[0]
        if result[5] == "Success": success_count += 1
        writer.writerow(result[:6] + [f"{success_count}/{NUM_REQUESTS}"] + result[6:])

logging.info(f"Test completato in {end_time - start_time:.2f} secondi. Report: {OUTPUT_FILE}")