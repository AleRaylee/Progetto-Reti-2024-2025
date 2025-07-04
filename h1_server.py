import os
import subprocess
import json
from datetime import datetime
from flask import Flask, request, jsonify
import socket 

# Configurazione
LOG_FILE = 'h1_command_log.json'
# Lista di comandi permessi. 
# Lo script permetterà solo che questi comandi vengono eseguiti.
ALLOWED_COMMANDS = [
    'ping',
    'ifconfig',
    'netstat',
    'hostname'
]

app = Flask(__name__)

def is_command_allowed(command):
    """Controlla se il comando è nella whitelist."""
    return any(command.strip().startswith(allowed) for allowed in ALLOWED_COMMANDS)

@app.route('/')
def index():
    """Pagina di benvenuto per confermare che il server è attivo."""
    hostname = socket.gethostname()
    return f"<h1>Command Server su {hostname}</h1><p>Invia una richiesta POST a /execute con il parametro 'command'.</p>"

@app.route('/execute', methods=['POST'])
def execute_command():
    """
    Endpoint per eseguire un comando.
    Accetta un parametro 'command' nel corpo della richiesta.
    """
    # Ottieni informazioni sulla richiesta
    source_ip = request.remote_addr
    command_to_run = request.values.get("command")
    
    # Log dell'evento di richiesta
    log_entry = {
        'timestamp': datetime.now().isoformat(),
        'source_ip': source_ip,
        'requested_command': command_to_run,
    }

    # Controlli di validita' dei commandi
    if not command_to_run:
        log_entry['status'] = 'error'
        log_entry['error_message'] = 'Parametro "command" mancante'
        log_request(log_entry)
        return jsonify(log_entry), 400

    if not is_command_allowed(command_to_run):
        log_entry['status'] = 'forbidden'
        log_entry['error_message'] = f"Comando non permesso: '{command_to_run}'"
        log_request(log_entry)
        return jsonify(log_entry), 403

    # --- Esecuzione del Comando ---
    print(f"Esecuzione comando da {source_ip}: {command_to_run}")
    try:
        result = subprocess.run(
            command_to_run,
            shell=True,
            capture_output=True,
            text=True,
            timeout=20
        )
        
        
        response_data = {
            'stdout': result.stdout.strip().splitlines(),
            'stderr': result.stderr.strip().splitlines(),
            'return_code': result.returncode
        }
        
        log_entry['status'] = 'success'
        log_entry['result'] = response_data
        
    except Exception as e:
        log_entry['status'] = 'execution_error'
        log_entry['error_message'] = str(e)

    # Salva il log e restituisci la risposta
    log_request(log_entry)
    return jsonify(log_entry)


def log_request(log_data):
    """Aggiunge una entry al file di log JSON."""
    try:
        # Carica i log esistenti se il file c'è, altrimenti crea una lista vuota
        if os.path.exists(LOG_FILE):
            with open(LOG_FILE, 'r') as f:
                logs = json.load(f)
        else:
            logs = []
        
        # Aggiunge il nuovo log
        logs.append(log_data)
        
        # Scrive di nuovo l'intero file di log
        with open(LOG_FILE, 'w') as f:
            json.dump(logs, f, indent=4)
    except (IOError, json.JSONDecodeError) as e:
        # Aggiunto controllo per file JSON corrotto
        print(f"!!! Errore durante la scrittura del log: {e}")
        # In caso di file corrotto, potremmo volerlo sovrascrivere
        try:
            with open(LOG_FILE, 'w') as f:
                json.dump([log_data], f, indent=4)
            print("!!! Il file di log era corrotto ed è stato sovrascritto con l'ultimo log.")
        except IOError as e_write:
            print(f"!!! Impossibile sovrascrivere il file di log corrotto: {e_write}")


if __name__ == '__main__':
    # Ascolta su tutte le interfacce sulla porta 8001
    app.run(host='0.0.0.0', port=8001, debug=False)



