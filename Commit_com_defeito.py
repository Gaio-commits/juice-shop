# -*- coding: utf-8 -*-

"""
AVISO: ESTE CÓDIGO É INTENCIONALMENTE INSEGURO E MAL ESCRITO.
FOI CRIADO APENAS PARA FINS EDUCACIONAIS.
NÃO USE NENHUMA PARTE DESTE CÓDIGO EM PROJETOS REAIS.
"""

import os
import pickle
import base64
import hashlib
import sqlite3
import yaml # Se a versão correta estiver instalada, esta linha é perigosa.

# Falha 1: Segredos Expostos no Código (Hardcoded Secrets)
# Chaves de API e senhas nunca devem estar no código-fonte.
# Elas devem ser carregadas de variáveis de ambiente ou de um serviço de gerenciamento de segredos.
API_KEY = "key_super_secreta_12345"
DB_PASSWORD = "admin" # Pior ainda, uma senha óbvia.

# Configurando um banco de dados falso para o exemplo
conn = sqlite3.connect(':memory:')
cursor = conn.cursor()
cursor.execute("CREATE TABLE users (id INTEGER, name TEXT, password_hash TEXT)")
cursor.execute("INSERT INTO users VALUES (1, 'admin', '21232f297a57a5a743894a0e4a801fc3')") # Hash MD5 para 'admin'

def main_menu():
    # Falha 2: Má Indentação e Falta de Padrões
	# A indentação aqui está uma bagunça, misturando tabs e espaços.
    # Torna o código difícil de ler e propenso a erros.
    print("\n--- Aplicação Terrivelmente Insegura ---")
    print("1. Buscar usuário por ID (Vulnerável a SQL Injection)")
    print("2. Pingar um site (Vulnerável a Command Injection)")
    print("3. Carregar perfil de usuário (Vulnerável a Desserialização Insegura)")
    print("4. Ler arquivo de log (Vulnerável a Path Traversal)")
    print("5. Carregar configuração YAML (Biblioteca Vulnerável)")
    print("6. Sair")
    return input("Escolha uma opção: ")

# Falha 3: Injeção de SQL (SQL Injection)
def get_user_by_id(user_id):
    """
    Busca um usuário no banco de dados.
    A query é construída concatenando a entrada do usuário diretamente, o que é uma péssima ideia.
    Um atacante pode injetar código SQL. Exemplo de entrada maliciosa: '1 OR 1=1'
    """
    print(f"Buscando dados para o ID: {user_id}")
    # A forma correta seria usar queries parametrizadas (ex: cursor.execute("SELECT * FROM users WHERE id=?", (user_id,)))
    query = f"SELECT * FROM users WHERE id = {user_id}"
    print(f"Executando query: {query}")
    try:
     cursor.execute(query)
     result = cursor.fetchone()
     if result:
        print(f"Usuário encontrado: {result}")
     else:
        print("Usuário não encontrado.")
    except Exception as e:
        # Falha 4: Tratamento de Erro Inseguro
        # Expor detalhes do erro pode dar dicas valiosas para um atacante.
        print(f"[ERRO GRAVE] Detalhes do erro de banco de dados: {e}")

# Falha 5: Injeção de Comando (Command Injection)
def ping_website(website):
    """
    Usa o comando ping do sistema.
    A entrada do usuário é passada diretamente para o shell do sistema.
    Um atacante pode injetar comandos. Exemplo de entrada maliciosa: 'google.com; ls -la'
    """
    print(f"Pingando {website}...")
    # A forma correta seria usar módulos como `subprocess` com `shell=False` e validar a entrada.
    os.system(f"ping -c 1 {website}")

# Falha 6: Desserialização Insegura com Pickle
def load_user_profile(profile_data):
    """
    Carrega dados de um perfil serializado.
    `pickle` é perigoso porque pode executar código arbitrário contido nos dados.
    Um atacante pode criar um payload malicioso que, ao ser desserializado, compromete o servidor.
    """
    try:
        decoded_data = base64.b64decode(profile_data)
        profile = pickle.loads(decoded_data)
        print("Perfil do usuário carregado:")
        print(profile)
    except Exception as e:
        print(f"[ERRO] Falha ao desserializar o perfil
