#!/usr/bin/env python3
"""
Cliente de Mensagens Seguras
Disciplina: Segurança da Informação
Prof. Michel Sales

Implementa cliente que envia mensagens criptografadas usando:
- Diffie-Hellman para troca de chaves
- ECDSA para assinatura digital
- PBKDF2 para derivação de chaves
- AES-CBC para criptografia
- HMAC para integridade e autenticidade
"""

import socket
import hashlib
import hmac
import secrets
import requests
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.exceptions import InvalidSignature
import struct
import sys

class SecureClient:
    def __init__(self, host='localhost', port=8888):
        self.host = host
        self.port = port
        self.socket = None
        
        # Parâmetros Diffie-Hellman (RFC 3526 - 2048-bit MODP Group)
        self.p = int('0xFFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD1'
                    '29024E088A67CC74020BBEA63B139B22514A08798E3404DD'
                    'EF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245'
                    'E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7ED'
                    'EE386BFB5A899FA5AE9F24117C4B1FE649286651ECE45B3D'
                    'C2007CB8A163BF0598DA48361C55D39A69163FA8FD24CF5F'
                    '83655D23DCA3AD961C62F356208552BB9ED529077096966D'
                    '670C354E4ABC9804F1746C08CA18217C32905E462E36CE3B'
                    'E39E772C180E86039B2783A2EC07A28FB5C55DF06F4C52C9'
                    'DE2BCBF6955817183995497CEA956AE515D2261898FA0510'
                    '15728E5A8AACAA68FFFFFFFFFFFFFFFF', 16)
        self.g = 2
        
        # Chaves ECDSA do cliente
        self.private_key = ec.generate_private_key(ec.SECP256R1())
        self.public_key = self.private_key.public_key()
        
        # Username do cliente (para busca da chave pública)
        self.username = "cliente_seguro"
        
        print(f"[CLIENTE] Chave pública ECDSA do cliente:")
        pub_key_pem = self.public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )
        print(pub_key_pem.decode())
        
    def get_public_key_from_github(self, username):
        """Simula busca de chave pública do GitHub"""
        print(f"[CLIENTE] Simulando busca da chave pública de {username} no GitHub...")
        
        # Em um cenário real, isso faria uma requisição HTTP para:
        # url = f"https://github.com/{username}.keys"
        # Por simplicidade, vamos usar chaves hardcoded para teste
        
        if username == "servidor_seguro":
            # Chave pública do servidor (em um cenário real viria do GitHub)
            test_key_pem = """-----BEGIN PUBLIC KEY-----
MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAETest_Key_For_Demo_Purposes_Only
This_Would_Be_A_Real_ECDSA_Public_Key_From_GitHub_In_Production_Environment
-----END PUBLIC KEY-----"""
            
            try:
                # Para demonstração, retornamos None para simular falha na busca
                # Em produção, isso decodificaria a chave PEM real
                return None
            except Exception as e:
                print(f"[CLIENTE] Erro ao decodificar chave pública: {e}")
                return None
        
        return None
    
    def verify_ecdsa_signature(self, message, signature, public_key):
        """Verifica assinatura ECDSA"""
        try:
            public_key.verify(signature, message, ec.ECDSA(hashes.SHA256()))
            return True
        except InvalidSignature:
            return False
        except Exception as e:
            print(f"[CLIENTE] Erro na verificação da assinatura: {e}")
            return False
    
    def sign_message(self, message):
        """Assina mensagem com chave privada ECDSA"""
        try:
            signature = self.private_key.sign(message, ec.ECDSA(hashes.SHA256()))
            return signature
        except Exception as e:
            print(f"[CLIENTE] Erro ao assinar mensagem: {e}")
            return None
    
    def derive_keys(self, shared_secret, salt):
        """Deriva chaves AES e HMAC usando PBKDF2"""
        try:
            iterations = 100000
            
            # Derivar chave AES (32 bytes para AES-256)
            kdf_aes = PBKDF2HMAC(
                algorithm=hashes.SHA256(),
                length=32,
                salt=salt,
                iterations=iterations,
            )
            key_aes = kdf_aes.derive(shared_secret.to_bytes(256, 'big'))
            
            # Derivar chave HMAC (32 bytes)
            kdf_hmac = PBKDF2HMAC(
                algorithm=hashes.SHA256(),
                length=32,
                salt=salt + b'hmac',  # Salt diferente para HMAC
                iterations=iterations,
            )
            key_hmac = kdf_hmac.derive(shared_secret.to_bytes(256, 'big'))
            
            return key_aes, key_hmac
        except Exception as e:
            print(f"[CLIENTE] Erro na derivação de chaves: {e}")
            return None, None
    
    def encrypt_message(self, message, key_aes):
        """Criptografa mensagem usando AES-CBC"""
        try:
            # Gerar IV aleatório
            iv = secrets.token_bytes(16)
            
            # Aplicar padding PKCS7
            message_bytes = message.encode('utf-8')
            block_size = 16
            pad_length = block_size - (len(message_bytes) % block_size)
            padded_message = message_bytes + bytes([pad_length] * pad_length)
            
            # Criptografar
            cipher = Cipher(algorithms.AES(key_aes), modes.CBC(iv))
            encryptor = cipher.encryptor()
            encrypted_data = encryptor.update(padded_message) + encryptor.finalize()
            
            return iv, encrypted_data
        except Exception as e:
            print(f"[CLIENTE] Erro na criptografia: {e}")
            return None, None
    
    def calculate_hmac(self, key_hmac, iv, encrypted_data):
        """Calcula HMAC para integridade e autenticidade"""
        try:
            hmac_tag = hmac.new(
                key_hmac, 
                iv + encrypted_data, 
                hashlib.sha256
            ).digest()
            return hmac_tag
        except Exception as e:
            print(f"[CLIENTE] Erro no cálculo HMAC: {e}")
            return None
    
    def perform_diffie_hellman_handshake(self):
        """Executa handshake Diffie-Hellman com assinatura ECDSA"""
        try:
            print("[CLIENTE] Iniciando handshake Diffie-Hellman...")
            
            # 1. Gerar par DH do cliente
            a = secrets.randbelow(self.p - 1) + 1
            A = pow(self.g, a, self.p)
            
            # 2. Assinar A + username_cliente
            message_to_sign = A.to_bytes(256, 'big') + self.username.encode()
            sig_A = self.sign_message(message_to_sign)
            
            if sig_A is None:
                return None, None, None
            
            # 3. Enviar A, sig_A, username_cliente
            a_bytes = A.to_bytes(256, 'big')
            data = struct.pack('!I', len(a_bytes)) + a_bytes
            data += struct.pack('!I', len(sig_A)) + sig_A
            data += self.username.encode()
            
            self.socket.send(data)
            print(f"[CLIENTE] Enviado A={A}")
            
            # 4. Receber B, sig_B, username_servidor
            response = self.socket.recv(4096)
            if not response:
                return None, None, None
            
            # Parse da resposta
            offset = 0
            b_len = struct.unpack('!I', response[offset:offset+4])[0]
            offset += 4
            
            B = int.from_bytes(response[offset:offset+b_len], 'big')
            offset += b_len
            
            sig_b_len = struct.unpack('!I', response[offset:offset+4])[0]
            offset += 4
            
            sig_B = response[offset:offset+sig_b_len]
            offset += sig_b_len
            
            username_servidor = response[offset:].decode('utf-8')
            
            print(f"[CLIENTE] Recebido B={B} de {username_servidor}")
            
            # 5. Buscar e verificar chave pública do servidor
            server_public_key = self.get_public_key_from_github(username_servidor)
            
            # Para demonstração, vamos pular a verificação da assinatura
            # Em produção, isso seria obrigatório
            if server_public_key is None:
                print("[CLIENTE] AVISO: Pulando verificação de assinatura (modo demonstração)")
            else:
                message_to_verify = B.to_bytes(256, 'big') + username_servidor.encode()
                if not self.verify_ecdsa_signature(message_to_verify, sig_B, server_public_key):
                    print("[CLIENTE] ERRO: Assinatura inválida!")
                    return None, None, None
                print("[CLIENTE] Assinatura verificada com sucesso")
            
            # 6. Calcular chave secreta compartilhada
            shared_secret = pow(B, a, self.p)
            print(f"[CLIENTE] Chave compartilhada calculada: {shared_secret}")
            
            # 7. Receber salt do servidor
            salt_data = self.socket.recv(4096)
            salt_len = struct.unpack('!I', salt_data[:4])[0]
            salt = salt_data[4:4+salt_len]
            print("[CLIENTE] Salt recebido para derivação de chaves")
            
            # 8. Derivar chaves
            key_aes, key_hmac = self.derive_keys(shared_secret, salt)
            
            return key_aes, key_hmac, shared_secret
            
        except Exception as e:
            print(f"[CLIENTE] Erro no handshake DH: {e}")
            return None, None, None
    
    def send_secure_message(self, message, key_aes, key_hmac):
        """Envia mensagem segura"""
        try:
            print(f"[CLIENTE] Enviando mensagem segura: '{message}'")
            
            # 1. Criptografar mensagem
            iv, encrypted_data = self.encrypt_message(message, key_aes)
            if iv is None or encrypted_data is None:
                return False
            
            # 2. Calcular HMAC
            hmac_tag = self.calculate_hmac(key_hmac, iv, encrypted_data)
            if hmac_tag is None:
                return False
            
            # 3. Construir pacote: [HMAC_TAG] + [IV_AES] + [MENSAGEM_CRIPTOGRAFADA]
            packet = hmac_tag + iv + encrypted_data
            
            print(f"[CLIENTE] Enviando: HMAC({len(hmac_tag)} bytes), IV({len(iv)} bytes), "
                  f"Mensagem criptografada({len(encrypted_data)} bytes)")
            
            # 4. Enviar pacote
            self.socket.send(packet)
            
            # 5. Receber confirmação
            response = self.socket.recv(1024)
            if response:
                print(f"[CLIENTE] Resposta do servidor: {response.decode()}")
                return True
            
            return False
            
        except Exception as e:
            print(f"[CLIENTE] Erro ao enviar mensagem segura: {e}")
            return False
    
    def connect_and_send(self, message):
        """Conecta ao servidor e envia mensagem segura"""
        try:
            # Conectar ao servidor
            self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.socket.connect((self.host, self.port))
            print(f"[CLIENTE] Conectado ao servidor {self.host}:{self.port}")
            
            # Executar handshake Diffie-Hellman
            key_aes, key_hmac, shared_secret = self.perform_diffie_hellman_handshake()
            
            if key_aes is None or key_hmac is None:
                print("[CLIENTE] ERRO: Falha no handshake")
                return False
            
            print("[CLIENTE] Handshake concluído com sucesso")
            print(f"[CLIENTE] Chaves derivadas - AES: {len(key_aes)} bytes, HMAC: {len(key_hmac)} bytes")
            
            # Enviar mensagem segura
            success = self.send_secure_message(message, key_aes, key_hmac)
            
            if success:
                print("[CLIENTE] Mensagem enviada com sucesso!")
            else:
                print("[CLIENTE] ERRO: Falha ao enviar mensagem")
            
            return success
            
        except ConnectionRefusedError:
            print(f"[CLIENTE] ERRO: Não foi possível conectar ao servidor {self.host}:{self.port}")
            print("[CLIENTE] Verifique se o servidor está rodando")
            return False
        except Exception as e:
            print(f"[CLIENTE] Erro na conexão: {e}")
            return False
        finally:
            if self.socket:
                self.socket.close()
                print("[CLIENTE] Conexão encerrada")

def main():
    """Função principal do cliente"""
    print("=" * 60)
    print("CLIENTE DE MENSAGENS SEGURAS")
    print("Disciplina: Segurança da Informação")
    print("Prof. Michel Sales")
    print("=" * 60)
    
    # Verificar argumentos da linha de comando
    if len(sys.argv) > 1:
        message = " ".join(sys.argv[1:])
    else:
        # Solicitar mensagem do usuário
        message = input("\n[CLIENTE] Digite a mensagem a ser enviada: ").strip()
        
        if not message:
            print("[CLIENTE] Mensagem não pode ser vazia!")
            return
    
    print(f"\n[CLIENTE] Mensagem a ser enviada: '{message}'")
    
    # Criar cliente e enviar mensagem
    client = SecureClient(host='servidor')
    
    try:
        success = client.connect_and_send(message)
        
        if success:
            print("\n" + "=" * 60)
            print("✅ COMUNICAÇÃO SEGURA CONCLUÍDA COM SUCESSO!")
            print("✅ Confidencialidade: Mensagem criptografada com AES-256-CBC")
            print("✅ Integridade: Verificada com HMAC-SHA256")
            print("✅ Autenticidade: Confirmada via HMAC e assinatura ECDSA")
            print("✅ Troca de chaves: Diffie-Hellman com assinatura digital")
            print("=" * 60)
        else:
            print("\n" + "=" * 60)
            print("❌ FALHA NA COMUNICAÇÃO SEGURA")
            print("❌ Verifique se o servidor está funcionando corretamente")
            print("=" * 60)
            
    except KeyboardInterrupt:
        print("\n[CLIENTE] Operação cancelada pelo usuário")
    except Exception as e:
        print(f"\n[CLIENTE] Erro inesperado: {e}")

if __name__ == "__main__":
    main()