FROM python:3.9-slim

WORKDIR /app

# Copia o arquivo de dependências para o contêiner
COPY requirements.txt .

# Instala as dependências listadas no requirements.txt
RUN pip install --no-cache-dir -r requirements.txt

# Copia o restante do código da aplicação (opcional, pois usaremos volumes no compose)
COPY app/ .

# Expõe a porta que o servidor usará
EXPOSE 8888