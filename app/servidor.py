"""
Implementa servidor que recebe mensagens criptografadas usando:
- Diffie-Hellman para troca de chaves
- ECDSA para assinatura digital
- PBKDF2 para derivação de chaves
- AES-CBC para criptografia
- HMAC para integridade e autenticidade

Funções:
- get_public_key_from_github
- verify_ecdsa_signature
- sign_message
- derive_keys
- decrypt_message
- verify_hmac
- handle_diffie_hellman_handshake ✓
- handle_secure_message
- start_server
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

class SecureServer:
    def __init__(self, host='0.0.0.0', port=8888):
        self.host = host
        self.port = port
        self.socket = None
        
        # Parâmetros Diffie-Hellman a serem usados na função handle_diffie_hellman_handshake
        # p é o número primo e g é o gerador
        # seguindo a analogia do slide, essas são as cores que o servidor vai misturar e mandar para o cliente 
        # p é uma "base" para formar a cor privada e g é a cor comum que os dois vão usar.
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
        
        # Chaves ECDSA do servidor
        self.private_key = ec.generate_private_key(ec.SECP256R1())
        self.public_key = self.private_key.public_key()
        
        # Username do servidor (para busca da chave pública)
        self.username = "servidor_seguro"
        
        print(f"[SERVIDOR] Chave pública ECDSA do servidor:")
        pub_key_pem = self.public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )
        print(pub_key_pem.decode())
        
    def get_public_key_from_github(self, username):
        """Simula busca de chave pública do GitHub"""
        print(f"[SERVIDOR] Simulando busca da chave pública de {username} no GitHub...")
        
        # Em um cenário real, isso faria uma requisição HTTP para:
        # url = f"https://github.com/{username}.keys"
        # Por simplicidade, vamos usar chaves hardcoded para teste
        
        if username == "cliente_seguro":
            # Chave pública do cliente (em um cenário real viria do GitHub)
            test_key_pem = """-----BEGIN PUBLIC KEY-----
MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAETest_Key_For_Demo_Purposes_Only
This_Would_Be_A_Real_ECDSA_Public_Key_From_GitHub_In_Production_Environment
-----END PUBLIC KEY-----"""
            
            try:
                # Para demonstração, retornamos None para simular falha na busca
                # Em produção, isso decodificaria a chave PEM real
                return None
            except Exception as e:
                print(f"[SERVIDOR] Erro ao decodificar chave pública: {e}")
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
            print(f"[SERVIDOR] Erro na verificação da assinatura: {e}")
            return False
    
    def sign_message(self, message):
        """Assina mensagem com chave privada ECDSA"""
        try:
            signature = self.private_key.sign(message, ec.ECDSA(hashes.SHA256()))
            return signature
        except Exception as e:
            print(f"[SERVIDOR] Erro ao assinar mensagem: {e}")
            return None
    
    def derive_keys(self, shared_secret, salt):
        """Deriva chaves AES e HMAC usando PBKDF2"""
        # Usa a biblioteca cryptography
        # Gera duas chaves distintas para o AES e HMAC
        # aplica hash em cima de hash a cada iteração
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
            print(f"[SERVIDOR] Erro na derivação de chaves: {e}")
            return None, None
    
    def decrypt_message(self, encrypted_data, key_aes, iv):
        """Descriptografa mensagem usando AES-CBC"""
        try:
            cipher = Cipher(algorithms.AES(key_aes), modes.CBC(iv))
            decryptor = cipher.decryptor()
            padded_message = decryptor.update(encrypted_data) + decryptor.finalize()
            
            # Remove padding PKCS7
            pad_length = padded_message[-1]
            message = padded_message[:-pad_length]
            
            return message.decode('utf-8')
        except Exception as e:
            print(f"[SERVIDOR] Erro na descriptografia: {e}")
            return None
    
    def verify_hmac(self, key_hmac, iv, encrypted_data, received_hmac):
        """Verifica HMAC para integridade e autenticidade"""
        try:
            expected_hmac = hmac.new(
                key_hmac, 
                iv + encrypted_data, 
                hashlib.sha256
            ).digest()
            
            # Comparação em tempo constante
            return hmac.compare_digest(expected_hmac, received_hmac)
        except Exception as e:
            print(f"[SERVIDOR] Erro na verificação HMAC: {e}")
            return False
    
    def handle_diffie_hellman_handshake(self, client_socket):
        """Executa handshake Diffie-Hellman com assinatura ECDSA"""
        try:
            print("[SERVIDOR] Iniciando handshake Diffie-Hellman...")
            
            # Recebe  A, sig_a e username_cliente
            # A pode ser entendido como a mistura de cores do cliente
            # Já sig_a é a assinatura digital ECDSA que garante a autenticidade, integridade e não repúdio.
            data = client_socket.recv(4096)
            if not data:
                return None, None, None
            
            # Parse dos dados recebidos (formato: len(A) + A + len(sig_A) + sig_A + username)
            offset = 0
            a_len = struct.unpack('!I', data[offset:offset+4])[0]
            offset += 4
            
            A = int.from_bytes(data[offset:offset+a_len], 'big')
            offset += a_len
            
            sig_a_len = struct.unpack('!I', data[offset:offset+4])[0]
            offset += 4
            
            sig_A = data[offset:offset+sig_a_len]
            offset += sig_a_len
            
            username_cliente = data[offset:].decode('utf-8')
            
            print(f"[SERVIDOR] Recebido A={A} de {username_cliente}")
            
            # 2. Buscar e verificar chave pública do cliente
            client_public_key = self.get_public_key_from_github(username_cliente)
            
            # Para demonstração, vamos pular a verificação da assinatura
            # Em produção, isso seria obrigatório
            if client_public_key is None:
                print("[SERVIDOR] AVISO: Pulando verificação de assinatura (modo demonstração)")
            else:
                message_to_verify = A.to_bytes(256, 'big') + username_cliente.encode()
                if not self.verify_ecdsa_signature(message_to_verify, sig_A, client_public_key):
                    print("[SERVIDOR] ERRO: Assinatura inválida!")
                    return None, None, None
                print("[SERVIDOR] Assinatura verificada com sucesso")
            
            # 3. Gerar par DH do servidor
            # b é a cor secreta escolhida pelo servidor usando o número primo como base
            # B é a mistura da cor privada com a cor comum
            b = secrets.randbelow(self.p - 1) + 1
            B = pow(self.g, b, self.p)
            

            # 4. Assina a mistura de cores junto ao seu username usando ECDSA.
            message_to_sign = B.to_bytes(256, 'big') + self.username.encode()
            sig_B = self.sign_message(message_to_sign)
            
            if sig_B is None:
                return None, None, None
            
            # 5. Enviar B, sig_B, username_servidor
            b_bytes = B.to_bytes(256, 'big')
            response = struct.pack('!I', len(b_bytes)) + b_bytes
            response += struct.pack('!I', len(sig_B)) + sig_B
            response += self.username.encode()
            
            client_socket.send(response)
            print(f"[SERVIDOR] Enviado B={B}")
            
            # 6. Calcular chave secreta compartilhada
            # É a mistura de cores final que será idêntica para o cliente e para o servidor.
            shared_secret = pow(A, b, self.p)
            print(f"[SERVIDOR] Chave compartilhada calculada: {shared_secret}")
            
            # 7. Gerar salt e enviar para o cliente
            # Usa o segredo do diff hellman em conjunto com o salt como entrada
            # para o AES e para o HMAC.
            salt = secrets.token_bytes(32)
            client_socket.send(struct.pack('!I', len(salt)) + salt)
            print("[SERVIDOR] Salt enviado para derivação de chaves")
            
            # 8. Derivar chaves
            # Usa a chave secreta do Diffie-Hellman como base para gerar duas chaves diferentes
            # para o AES e o HMAC a partir do PBKDF2.
            key_aes, key_hmac = self.derive_keys(shared_secret, salt)
            
            return key_aes, key_hmac, shared_secret
            
        except Exception as e:
            print(f"[SERVIDOR] Erro no handshake DH: {e}")
            return None, None, None
    
    def handle_secure_message(self, client_socket, key_aes, key_hmac):
        """Recebe e processa mensagem segura"""
        try:
            print("[SERVIDOR] Aguardando mensagem segura...")
            
            # Receber mensagem: [HMAC_TAG] + [IV_AES] + [MENSAGEM_CRIPTOGRAFADA]
            data = client_socket.recv(4096)
            if not data:
                return False
            
            # Parse da mensagem
            hmac_tag = data[:32]  # HMAC-SHA256 = 32 bytes
            iv = data[32:48]      # AES IV = 16 bytes
            encrypted_message = data[48:]
            
            print(f"[SERVIDOR] Recebido: HMAC({len(hmac_tag)} bytes), IV({len(iv)} bytes), "
                  f"Mensagem criptografada({len(encrypted_message)} bytes)")
            
            # Verificar HMAC
            if not self.verify_hmac(key_hmac, iv, encrypted_message, hmac_tag):
                print("[SERVIDOR] ERRO: HMAC inválido! Mensagem rejeitada.")
                return False
            
            print("[SERVIDOR] HMAC verificado com sucesso - Integridade e autenticidade confirmadas")
            
            # Descriptografar mensagem
            decrypted_message = self.decrypt_message(encrypted_message, key_aes, iv)
            if decrypted_message is None:
                print("[SERVIDOR] ERRO: Falha na descriptografia")
                return False
            
            print(f"[SERVIDOR] Mensagem recebida e descriptografada: '{decrypted_message}'")
            
            # Enviar confirmação
            response = "Mensagem recebida com sucesso!"
            client_socket.send(response.encode())
            
            return True
            
        except Exception as e:
            print(f"[SERVIDOR] Erro ao processar mensagem segura: {e}")
            return False
    
    def start_server(self):
        """Inicia o servidor"""
        try:
            self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            self.socket.bind((self.host, self.port))
            self.socket.listen(1)
            
            print(f"[SERVIDOR] Servidor iniciado em {self.host}:{self.port}")
            print("[SERVIDOR] Aguardando conexão do cliente...")
            
            while True:
                client_socket, address = self.socket.accept()
                print(f"[SERVIDOR] Cliente conectado de {address}")
                
                try:
                    # Executar handshake Diffie-Hellman
                    key_aes, key_hmac, shared_secret = self.handle_diffie_hellman_handshake(client_socket)
                    
                    if key_aes is None or key_hmac is None:
                        print("[SERVIDOR] ERRO: Falha no handshake")
                        client_socket.close()
                        continue
                    
                    print("[SERVIDOR] Handshake concluído com sucesso")
                    
                    # Processar mensagem segura
                    if self.handle_secure_message(client_socket, key_aes, key_hmac):
                        print("[SERVIDOR] Comunicação segura concluída com sucesso")
                    else:
                        print("[SERVIDOR] ERRO: Falha na comunicação segura")
                    
                except Exception as e:
                    print(f"[SERVIDOR] Erro ao processar cliente: {e}")
                finally:
                    client_socket.close()
                    print("[SERVIDOR] Conexão com cliente encerrada")
                
        except KeyboardInterrupt:
            print("\n[SERVIDOR] Servidor interrompido pelo usuário")
        except Exception as e:
            print(f"[SERVIDOR] Erro no servidor: {e}")
        finally:
            if self.socket:
                self.socket.close()
                print("[SERVIDOR] Socket do servidor fechado")

def main():
    server = SecureServer()
    server.start_server()

if __name__ == "__main__":
    main()
