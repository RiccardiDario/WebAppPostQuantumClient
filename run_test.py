# Configurazioni da testare
#kem_list = ["secp256r1", "mlkem512", "p256_mlkem512", "secp384r1", "mlkem768", "p384_mlkem768", "secp521r1", "mlkem1024","p521_mlkem1024"]

import subprocess, time, re, os
kem_list = ["secp256r1", "mlkem512", "p256_mlkem512"]
NUM_RUNS, TIMEOUT, SLEEP = 5, 300, 2
CLIENT = "client"
CLIENT_DONE = r"\[INFO\] Test completato in .* Report: /app/output/request_logs/request_client\d+\.csv"
START_CLIENT_PATH = os.path.abspath("start_client.py")


def run_subprocess(command, timeout=None):
    """Esegue un comando e forza la chiusura del processo"""
    try:
        proc = subprocess.Popen(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, encoding="utf-8", errors="replace")
        stdout, stderr = proc.communicate(timeout=timeout)
        return proc.returncode, stdout, stderr
    except subprocess.TimeoutExpired:
        proc.terminate()
        try:
            proc.wait(timeout=2)
        except subprocess.TimeoutExpired:
            proc.kill()
        return -1, "", "⏱️ Timeout scaduto. Processo terminato forzatamente."

def check_logs(container, pattern):
    code, stdout, stderr = run_subprocess(["docker", "logs", "--tail", "100", container], timeout=5)
    if stdout:
        return re.search(pattern, stdout) is not None
    return False


def update_kem(kem):
    with open(START_CLIENT_PATH, "r", encoding="utf-8") as f:
        content = re.sub(r'("--curves",\s*")[^"]+(")', f'\\1{kem}\\2', f.read())
    with open(START_CLIENT_PATH, "w", encoding="utf-8") as f:
        f.write(content)
    print(f"✅ KEM aggiornato: {kem}")

def run_single_test(i):
    print(f"\n🚀 Test {i} in corso...")

    # Avvio container
    code, _, err = run_subprocess(["docker-compose", "up", "-d"], timeout=30)
    if code != 0:
        print(f"❌ Errore avvio container: {err}")
        return

    print("⌛ In attesa completamento log...")

    start = time.time()
    while time.time() - start < TIMEOUT:
        if check_logs(CLIENT, CLIENT_DONE):
            print(f"✅ Test {i} completato.")
            break
        time.sleep(SLEEP)
    else:
        print(f"⚠️ Timeout test {i} dopo {TIMEOUT} secondi.")

    print("🛑 Arresto container...")
    run_subprocess(["docker-compose", "down"], timeout=30)

    print("🧹 Rimozione volumi specifici...")
    for volume in ["webapppostquantum_pcap", "webapppostquantum_tls_keys"]:
        run_subprocess(["docker", "volume", "rm", "-f", volume])

    if i < NUM_RUNS:
        time.sleep(SLEEP)

# Esecuzione principale
for kem in kem_list:
    print(f"\n🔁 Inizio test per KEM: {kem}")
    update_kem(kem)

    for i in range(1, NUM_RUNS + 1):
        run_single_test(i)

print("\n🎉 Tutti i test completati con successo!")
