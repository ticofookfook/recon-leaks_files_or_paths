import requests
import re
import sys
import argparse
from concurrent.futures import ThreadPoolExecutor, as_completed
import random
import warnings
from dotenv import load_dotenv
import os
from pathlib import Path
from secrets_patterns import SECRETS_PATTERNS
from tqdm import tqdm  # Se não tiver: pip install tqdm

warnings.filterwarnings("ignore", message="Unverified HTTPS request")
load_dotenv(dotenv_path=os.path.join(os.path.dirname(__file__), '..', '.env'))

THREADS_GET_PAGE_FIND_LEAKS = int(os.getenv('THREADS_GET_PAGE_FIND_LEAKS', 50))
DETAILED = True

# Mapa para armazenar segredos encontrados
secrets = set()
processed_count = 0

def process_file(file_path):
    """Processa um único arquivo em busca de vulnerabilidades"""
    global processed_count
    try:
        with open(file_path, 'r', encoding='utf-8', errors='ignore') as file:
            content = file.read()
    except Exception as e:
        return []
    
    vulnerabilities = []
    
    for pattern in SECRETS_PATTERNS:
        for match in pattern.finditer(content):
            secret = match.group(0)
            if secret in secrets:
                continue
            secrets.add(secret)
            
            vulnerability = {
                'file': str(file_path), 
                'leak': secret
            }
            vulnerabilities.append(vulnerability)
            
            if DETAILED:
                lines = content.split('\n')
                for i, line in enumerate(lines):
                    if secret in line:
                        vulnerability['line_number'] = i + 1
                        vulnerability['line_content'] = line.strip()
                        break
    
    return vulnerabilities

def scan_local_files(path, extensions=None):
    """
    Escaneia arquivos locais em busca de secrets
    """
    files = get_files_from_path(path, extensions)
    
    if not files:
        print(f"Nenhum arquivo encontrado em: {path}")
        return []
    
    print(f"📊 Escaneando {len(files)} arquivos...")
    print(f"🔍 Total de padrões de busca: {len(SECRETS_PATTERNS)}")
    print(f"⚡ Usando {THREADS_GET_PAGE_FIND_LEAKS} threads")
    print(f"📈 Total de verificações: {len(files) * len(SECRETS_PATTERNS):,}")
    print("-" * 50)
    
    vulnerabilities = []
    
    # Com barra de progresso
    with ThreadPoolExecutor(max_workers=THREADS_GET_PAGE_FIND_LEAKS) as executor:
        # Submete todos os trabalhos
        futures = {executor.submit(process_file, file): file for file in files}
        
        # Processa conforme vão completando
        with tqdm(total=len(files), desc="Processando") as pbar:
            for future in as_completed(futures):
                result = future.result()
                if result:
                    vulnerabilities.extend(result)
                    # Mostra em tempo real quando acha algo
                    for vuln in result:
                        tqdm.write(f"🔑 Encontrado: {vuln['leak'][:50]}... em {Path(vuln['file']).name}")
                pbar.update(1)
    
    # MOSTRA OS RESULTADOS FINAIS
    print("\n" + "=" * 50)
    if vulnerabilities:
        print(f"🔴 Total: {len(vulnerabilities)} vazamentos em {len(secrets)} secrets únicos!")
    else:
        print("✅ Nenhum vazamento encontrado!")
    
    return vulnerabilities

def get_files_from_path(path, extensions=None):
    """
    Retorna lista de arquivos de um diretório ou arquivo único
    """
    path = Path(path)
    
    if path.is_file():
        return [path]
    
    if path.is_dir():
        if extensions:
            files = []
            for ext in extensions:
                files.extend(path.rglob(f'*{ext}'))
            return files
        else:
            return [f for f in path.rglob('*') if f.is_file()]
    
    return []

if __name__ == "__main__":
    if len(sys.argv) > 1:
        pasta = sys.argv[1]
    else:
        pasta = input("Digite o caminho da pasta para escanear: ")
    
    resultados = scan_local_files(pasta)
