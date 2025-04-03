import json, os, re, time, logging, subprocess, csv, psutil, pandas as pd
from threading import Thread, Lock
from datetime import datetime

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s", handlers=[logging.StreamHandler()])
OUTPUT_DIR, MONITOR_DIR, TRACE_LOG_DIR, AVG_DIR = "/app/output/request_logs", "/app/output/system_logs", "/app/logs/", "/app/output/request_logs/avg/"
for d in (OUTPUT_DIR, MONITOR_DIR, TRACE_LOG_DIR, AVG_DIR): os.makedirs(d, exist_ok=True)
NUM_REQUESTS, active_requests, active_requests_lock, global_stats = 500, 0, Lock(), {"cpu_usage": [], "memory_usage": []}
CURL_COMMAND_TEMPLATE = ["curl", "--tlsv1.3", "--curves", "mlkem1024", "--cacert", "/opt/certs/CA.crt", "-w",
"Connect Time: %{time_connect}, TLS Handshake: %{time_appconnect}, Total Time: %{time_total}, %{http_code}\n","-s", "https://nginx_pq:4433"]

def get_next_filename(base_path, base_name, extension):
    counter = 1
    while os.path.exists(filename := f"{base_path}/{base_name}{counter}.{extension}"): counter += 1
    return filename, counter
    
def monitor_system():
    """Monitora CPU, memoria e connessioni attive."""
    with open(MONITOR_FILE, "w", newline="", encoding="utf-8") as f:
        writer = csv.writer(f); writer.writerow(["Timestamp", "CPU_Usage(%)", "Memory_Usage(%)", "Active_TLS"])
        stable_counter = 0
        while True:
            with active_requests_lock: tls = active_requests
            writer.writerow([datetime.now().strftime("%Y-%m-%d %H:%M:%S.%f"), psutil.cpu_percent(), psutil.virtual_memory().percent, tls])
            if tls == 0: stable_counter += 1
            if stable_counter >= 5: break
            time.sleep(0.1)

def execute_request(req_num):
    global active_requests
    trace_file, cert_size, kem, sig_alg  = f"{TRACE_LOG_DIR}trace_{req_num}.log", 0, "Unknown", "Unknown"
    with active_requests_lock: active_requests += 1  
    try:
        start = time.time()
        process = subprocess.Popen(CURL_COMMAND_TEMPLATE + ["--trace", trace_file, "-o", "/dev/null"], stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        stdout, _ = process.communicate()
        elapsed_time = round((time.time() - start) * 1000, 3)
        bytes_sent = bytes_received = 0
        previous_line = ""
        if os.path.exists(trace_file):
            with open(trace_file, encoding="utf-8") as f:
                for line in f:
                    m_sent, m_recv = re.search(r"(=> Send SSL data, (\d+)|Send header, (\d+))", line), re.search(r"(<= Recv SSL data, (\d+)|Recv header, (\d+)|Recv data, (\d+))", line)
                    bytes_sent += int(m_sent.group(2) or m_sent.group(3)) if m_sent else 0
                    bytes_received += int(m_recv.group(2) or m_recv.group(3) or m_recv.group(4)) if m_recv else 0
                    if match_tls := re.search(r"SSL connection using TLSv1.3 / .* / (\S+) / (\S+)", line): kem = match_tls.group(1)
                    if match_sig := re.search(r"Certificate level 1: .* signed using ([^,]+)", line): sig_alg = match_sig.group(1)
                    if "TLS handshake, Certificate (11):" in previous_line and (match_cert_size := re.search(r"<= Recv SSL data, (\d+)", line)): cert_size = int(match_cert_size.group(1))
                    previous_line = line
        try:
            metrics = stdout.strip().rsplit(", ", 1)
            http_status = metrics[-1].strip()
            metrics_dict = {k + " (ms)": round(float(v[:-1]) * 1000, 3) for k, v in (item.split(": ") for item in metrics[0].split(", "))}
            connect_time, handshake_time, total_time = metrics_dict.get("Connect Time (ms)"), metrics_dict.get("TLS Handshake (ms)"), metrics_dict.get("Total Time (ms)")
            success_status = "Success" if http_status == "200" else "Failure"
        except Exception:
            logging.error(f"Errore parsing metriche richiesta {req_num}")
            connect_time = handshake_time = total_time = None
            success_status = "Failure"
        logging.info(f"Richiesta {req_num}: {success_status} | Connessione={connect_time} ms, Handshake={handshake_time} ms, Total_Time={total_time} ms, ElaspsedTime={elapsed_time} ms, Inviati={bytes_sent}, Ricevuti={bytes_received}, HTTP={http_status}, KEM={kem}, Firma={sig_alg}, Cert_Size={cert_size} B")
        return [req_num, connect_time, handshake_time, total_time, elapsed_time, success_status, bytes_sent, bytes_received, kem, sig_alg, cert_size]
    except Exception as e:
        logging.error(f"Errore richiesta {req_num}: {e}")
        return [req_num, None, None, None, None, "Failure", 0, 0, kem, sig_alg, cert_size]
    finally:
        with active_requests_lock: active_requests -= 1

def convert_to_bytes(value, unit):
    unit = unit.lower()
    value = float(value)
    units = {'b': 1, 'byte': 1, 'bytes': 1, 'kb': 1024, 'mb': 1024**2, 'gb': 1024**3}
    if unit in units: return int(value * units[unit])
    raise ValueError(f"Unità non riconosciuta: {unit}")

def analyze_pcap():
    pcap_file, tls_keylog_file = "/app/pcap/capture.pcap", "/tls_keys/tls-secrets.log"
    try:
        result = subprocess.run(["tshark", "-r", pcap_file, "-q", "-z", "conv,tcp"], capture_output=True, text=True, timeout=60)
        if result.returncode != 0:
            logging.error("Errore nell'analisi del file pcap con tshark")
            return 0, 0, 0, 0

        upload_bytes = download_bytes = num_connessioni = 0
        pattern = re.compile(r"(\d+\.\d+\.\d+\.\d+:\d+)\s+<->\s+(\d+\.\d+\.\d+\.\d+:\d+)\s+\d+\s+(\d+)\s+(\w+)\s+\d+\s+(\d+)\s+(\w+)")
        for line in result.stdout.split("\n"):
            match = pattern.search(line)
            if match:
                num_connessioni += 1
                download = convert_to_bytes(match.group(3), match.group(4))
                upload = convert_to_bytes(match.group(5), match.group(6))
                download_bytes += download; upload_bytes += upload

        tls_result = subprocess.run([ "tshark", "-r", pcap_file, "-Y", "tls.handshake", "-T", "fields",
            "-e", "ip.src", "-e", "tcp.srcport", "-e", "ip.dst", "-e", "tcp.dstport", "-e", "frame.len", "-e", "tls.handshake.type",
            "-o", f"tls.keylog_file:{tls_keylog_file}"], capture_output=True, text=True, timeout=60)

        tls_upload_bytes = tls_download_bytes = 0
        if tls_result.returncode == 0:
            for line in tls_result.stdout.splitlines():
                try:
                    fields = line.split("\t")
                    if len(fields) >= 6:
                        dst_ip, frame_size = fields[2], int(fields[4])
                        if dst_ip == "192.168.1.100": tls_upload_bytes += frame_size
                        else: tls_download_bytes += frame_size
                except ValueError: continue

        div = lambda x: x / num_connessioni if num_connessioni > 0 else 0
        avg_upload, avg_download = div(upload_bytes), div(download_bytes)
        avg_tls_upload, avg_tls_download = div(tls_upload_bytes), div(tls_download_bytes)

        logging.info(f"Numero connessioni individuate: {num_connessioni}")
        logging.info(f"Totale upload: {upload_bytes} bytes | Totale download: {download_bytes} bytes")
        logging.info(f"Media byte inviati: {avg_upload:.2f} B | Media byte ricevuti: {avg_download:.2f} B")
        logging.info(f"Media traffico TLS inviato: {avg_tls_upload:.2f} B | Media traffico TLS ricevuto: {avg_tls_download:.2f} B")

        return avg_upload, avg_download, avg_tls_upload, avg_tls_download
    except subprocess.TimeoutExpired:
        logging.error("Timeout durante l'esecuzione di tshark.")
        return 0, 0, 0, 0
    except Exception as e:
        logging.error(f"Errore durante l'analisi: {e}")
        return 0, 0, 0, 0

def update_average_report(request_results):
    """Genera il report delle medie globali per il batch corrente e aggiorna average_metrics.csv."""
    avg_file = os.path.join(AVG_DIR, "average_metrics.csv")
    success_results = [r for r in request_results if r[1] is not None]
    if not success_results:
        logging.warning("Nessuna richiesta di successo, il report delle medie non verrà aggiornato.")
        return

    mean = lambda idx: round(sum(r[idx] for r in success_results) / len(success_results), 4)
    avg_connect_time, avg_handshake_time = mean(1), mean(2)
    avg_total_time, avg_elapsed_time = mean(3), mean(4)
    avg_logical_bytes_sent, avg_logical_bytes_received = mean(6), mean(7)
    kem_used = next((r[8] for r in success_results if r[8] and r[8] != "Unknown"), "Unknown")
    sig_used = next((r[9] for r in success_results if r[9] and r[9] != "Unknown"), "Unknown")

    if os.path.exists(MONITOR_FILE):
        df = pd.read_csv(MONITOR_FILE)
        valid_cpu = df[df["CPU_Usage(%)"] > 0]["CPU_Usage(%)"]
        valid_ram = df[df["Memory_Usage(%)"] > 0]["Memory_Usage(%)"]
        avg_cpu = round(valid_cpu.mean(), 4) if not valid_cpu.empty else 0.0
        avg_ram = round(valid_ram.mean(), 4) if not valid_ram.empty else 0.0
    else: avg_cpu, avg_ram = 0.0, 0.0

    avg_upload, avg_download, avg_tls_upload, avg_tls_download = analyze_pcap()
    file_exists = os.path.exists(avg_file)
    with open(avg_file, "a", newline="", encoding="utf-8") as f:
        writer = csv.writer(f)
        if not file_exists:
            writer.writerow([
                "KEM", "Signature", "Avg_Connect_Time(ms)", "Avg_Handshake_Time(ms)",
                "Avg_Total_Time(ms)", "Avg_Elapsed_Time(ms)", "Client_Avg_CPU_Usage(%)",
                "Client_Avg_RAM_Usage(%)", "Avg_Upload_Bytes (Wireshark)", "Avg_Download_Bytes (Wireshark)",
                "Avg_TLS_Upload_Bytes (Wireshark)", "Avg_TLS_Download_Bytes (Wireshark)",
                "Avg_Logical_Bytes_Sent (cURL)", "Avg_Logical_Bytes_Received (cURL)"])
        writer.writerow([
            kem_used, sig_used, avg_connect_time, avg_handshake_time, avg_total_time,
            avg_elapsed_time, avg_cpu, avg_ram, avg_upload, avg_download,
            avg_tls_upload, avg_tls_download, avg_logical_bytes_sent, avg_logical_bytes_received])
    logging.info(f"Report delle medie aggiornato: {avg_file}")

def wait_and_lock_server():
    base_url_http = "http://nginx_pq"
    print("🔁 Sync con Nginx/Flask via HTTP (curl)...")
    while True:
        try:
            r = subprocess.run(["curl", "-s", f"{base_url_http}/status"],
                               stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, text=True)
            if r.returncode != 0 or not r.stdout.strip():
                raise Exception("Nessuna risposta")
            try:
                res = json.loads(r.stdout)
            except json.JSONDecodeError:
                raise Exception(f"Risposta non JSON valida: {r.stdout.strip()}")
            if res.get("ready") is True:
                print("⏳ Test in corso. Attendo riavvio server...")
            else:
                p = subprocess.run(["curl", "-s", "-X", "POST", f"{base_url_http}/ready"],
                                   stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
                if p.returncode == 0:
                    print("✅ Server lockato. Avvio richieste.")
                    break
        except Exception as e:
            print(f"❌ Server non pronto. Retry... ({e})")
        time.sleep(1)

OUTPUT_FILE, file_index = get_next_filename(OUTPUT_DIR, "request_client", "csv")
MONITOR_FILE, _ = get_next_filename(MONITOR_DIR, "system_client", "csv")
wait_and_lock_server()
with open(OUTPUT_FILE, "w", newline="", encoding="utf-8") as f:
    writer = csv.writer(f)
    writer.writerow(["Request_Number", "Connect_Time(ms)", "TLS_Handshake(ms)", "Total_Time(ms)", "Elapsed_Time(ms)", 
                     "Status", "Success_Count", "Bytes_Sent(B)", "Bytes_Received(B)", "KEM", "Signature", "Cert_Size(B)"])
    
    monitor_thread = Thread(target=monitor_system); monitor_thread.start()
    start_time = time.time()
    request_results = []  
    try:
        for i in range(NUM_REQUESTS):
            result = execute_request(i + 1)
            request_results.append(result)
        #Decommentare per avere le richieste parallele, commentando le tre righe superiori
        #with ThreadPoolExecutor(max_workers=NUM_REQUESTS) as executor:
            #futures = [executor.submit(execute_request, i + 1) for i in range(NUM_REQUESTS)]  
            #for future in as_completed(futures): request_results.append(future.result()) 
    finally:
        monitor_thread.join()
        end_time = time.time()
    
    kem_used  = next((r[8] for r in request_results if r[8] != "Unknown"), "Unknown")
    sig_used = next((r[9] for r in request_results if r[9] != "Unknown"), "Unknown")
    pd.read_csv(MONITOR_FILE).assign(KEM=kem_used, Signature=sig_used).to_csv(MONITOR_FILE, index=False)
    success_count = 0
    for result in request_results:
        request_number = result[0]
        if result[5] == "Success": success_count += 1
        writer.writerow(result[:6] + [f"{success_count}/{NUM_REQUESTS}"] + result[6:])

update_average_report(request_results)
logging.info(f"Test completato in {end_time - start_time:.2f} secondi. Report: {OUTPUT_FILE}")