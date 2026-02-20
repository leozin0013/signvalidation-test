FROM node:18-slim

# Instalar Python, curl e dependências do sistema
RUN apt-get update && apt-get install -y \
    python3 \
    python3-pip \
    curl \
    ca-certificates \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

# Copiar arquivos de dependências
COPY package*.json ./
COPY requirements.txt ./

# Instalar dependências Node.js
RUN npm install

# Copiar código fonte
COPY . .

# Compilar TypeScript
RUN npm run build

# Instalar dependências Python (--break-system-packages é seguro em containers Docker)
RUN pip3 install --no-cache-dir --break-system-packages -r requirements.txt

# Baixar TODOS os certificados da ICP-Brasil (~324 certificados)
# Inclui: todas ACs (ativas e expiradas), certificados para validar CRLs, cadeia completa
RUN mkdir -p /app/certs && \
    echo "Baixando todos os certificados ICP-Brasil..." && \
    python3 /app/download_all_icpbrasil_certs.py && \
    echo "Certificados instalados:" && \
    ls -la /app/certs/ | head -20 && \
    echo "..." && \
    echo "Total: $(ls /app/certs/*.crt /app/certs/*.cer 2>/dev/null | wc -l) certificados"

# Instalar TODOS os certificados no system trust store
RUN echo "Convertendo e instalando certificados no system trust store..." && \
    for cert in /app/certs/*.crt /app/certs/*.cer; do \
        if [ -f "$cert" ]; then \
            filename=$(basename "$cert"); \
            filename_noext="${filename%.*}"; \
            # Tentar converter DER para PEM (se já for PEM, openssl ignora o erro); \
            openssl x509 -inform DER -in "$cert" -out "/usr/local/share/ca-certificates/$filename_noext.crt" 2>/dev/null || \
            openssl x509 -inform PEM -in "$cert" -out "/usr/local/share/ca-certificates/$filename_noext.crt" 2>/dev/null || \
            cp "$cert" "/usr/local/share/ca-certificates/$filename_noext.crt"; \
        fi; \
    done && \
    update-ca-certificates && \
    echo "System trust store atualizado: $(ls /usr/local/share/ca-certificates/*.crt 2>/dev/null | wc -l) certificados instalados."

# Criar diretório de uploads
RUN mkdir -p uploads

# Expor porta
EXPOSE 3000

# Comando para iniciar
CMD ["npm", "start"]
