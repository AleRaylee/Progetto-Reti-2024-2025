import os
import subprocess
import json
import time
from datetime import datetime
import socket
import random
import struct


LOG_FILE = 'traceroute_log.json'


# IP Target
TARGET_HOSTS = [
    "10.0.0.2",   # h1
    "10.0.0.3",   # h2
    "11.0.0.2",   # h3
    "192.168.1.2",# h4
    "10.8.1.2"    # h5
]


def perform_trace(destination, max_hops=30):
    """Esegue un traceroute UDP e restituisce i risultati."""
    results = []
    
    try:
        dest_ip = socket.gethostbyname(destination)
    except socket.error as e:
        return [{'error': f'Impossibile risolvere {destination}: {e}'}]

    port = random.choice(range(33434, 33535))
    
    header = '{:<5} {:<20} {:<45} {:<10}'.format('Hop', 'Address', 'Host Name', 'Time')
    results.append(header)
    
    for ttl in range(1, max_hops + 1):
        try:
            receiver = create_receiver(port)
            sender = create_sender(ttl)
        except (IOError, OSError) as e:
            return [{'error': str(e)}]

        sender.sendto(b'', (destination, port))
        start_time = time.time()

        addr = None
        try:
            _, addr = receiver.recvfrom(1024)
        except socket.error:
            pass # Timeout
        finally:
            receiver.close()
            sender.close()

        end_time = time.time()
        response_time = round((end_time - start_time) * 1000, 2)

        if addr:
            curr_addr = addr[0]
            try:
                curr_name = socket.gethostbyaddr(curr_addr)[0]
            except socket.error:
                curr_name = curr_addr
            
            line = '{:<5} {:<20} {:<45} {:<10}'.format(ttl, curr_addr, curr_name, f'{response_time} ms')
            results.append(line)

            if curr_addr == dest_ip:
                results.append(f' Traceroute terminato ')
                break
        else:
            line = '{:<5} {:<20}'.format(ttl, '*')
            results.append(line)
    
    return results

def create_receiver(port):
    s = socket.socket(family=socket.AF_INET, type=socket.SOCK_RAW, proto=socket.IPPROTO_ICMP)
    timeout = struct.pack('ll', 1, 0)
    s.setsockopt(socket.SOL_SOCKET, socket.SO_RCVTIMEO, timeout)
    s.bind(('', port))
    return s

def create_sender(ttl):
    s = socket.socket(family=socket.AF_INET, type=socket.SOCK_DGRAM, proto=socket.IPPROTO_UDP)
    s.setsockopt(socket.SOL_IP, socket.IP_TTL, ttl)
    return s


def main():
    """
    Funzione principale che esegue un singolo ciclo di traceroute
    e salva i risultati su un file JSON.
    """
    print(">>> Avvio  del comando  traceroute...")
    print(f">>> Destinazioni: {TARGET_HOSTS}")
    
    final_log = {
        'run_timestamp': datetime.now().isoformat(),
        'traces': []
    }

    for host_ip in TARGET_HOSTS:
        print(f">>> Eseguendo traceroute dal server verso {host_ip}...")
        trace_output = perform_trace(host_ip)
        
        final_log['traces'].append({
            'destination': host_ip,
            'output': trace_output
        })
        print(f">>> Traceroute verso {host_ip} completato.")
        print("\n--- Risultato per {} ---".format(host_ip))
        for line in trace_output:
            print(line)
        print("------------------------\n")

    try:
        with open(LOG_FILE, 'w') as f:
            json.dump(final_log, f, indent=4)
        print(f">>> Risultati completi salvati in {LOG_FILE}")
    except IOError as e:
        print(f" Errore durante la scrittura del file di log: {e}")

    print(">>> Traceroute completato. Lo script terminerà.")


if __name__ == "__main__":
    if os.geteuid() != 0:
        print("!!! Errore: Questo script richiede privilegi di root (esegui con 'sudo').")
    else:
        main()