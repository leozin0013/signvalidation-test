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

# Baixar cadeia completa de certificados Gov.br (RAIZ + intermediárias + finais)
RUN mkdir -p /app/certs && \
    echo "Baixando certificados ICP-Brasil RAIZ..." && \
    cd /app/certs && \
    curl -sS -o ICP-Brasilv2.crt http://acraiz.icpbrasil.gov.br/credenciadas/RAIZ/ICP-Brasilv2.crt || true && \
    curl -sS -o ICP-Brasilv5.crt http://acraiz.icpbrasil.gov.br/credenciadas/RAIZ/ICP-Brasilv5.crt || true && \
    curl -sS -o ICP-Brasilv10.crt http://acraiz.icpbrasil.gov.br/credenciadas/RAIZ/ICP-Brasilv10.crt || true && \
    curl -sS -o ICP-Brasilv11.crt http://acraiz.icpbrasil.gov.br/credenciadas/RAIZ/ICP-Brasilv11.crt || true && \
    curl -sS -o ICP-Brasilv12.crt http://acraiz.icpbrasil.gov.br/credenciadas/RAIZ/ICP-Brasilv12.crt || true && \
    curl -sS -o ICP-Brasilv13.crt http://acraiz.icpbrasil.gov.br/credenciadas/RAIZ/ICP-Brasilv13.crt || true && \
    echo "Baixando cadeia Gov.br completa..." && \
    curl -sS -o Cadeia_GovBr-der.p7b http://repo.iti.br/docs/Cadeia_GovBr-der.p7b || true && \
    echo "Extraindo certificados do bundle Gov.br..." && \
    python3 /app/download_govbr_chain.py || true && \
    echo "Certificados instalados:" && \
    ls -la /app/certs/

# Instalar TODOS os certificados no system trust store (RAIZ + Gov.br)
RUN echo "Convertendo certificados DER para PEM e instalando no system trust store..." && \
    for cert in /app/certs/*.crt; do \
        if [ -f "$cert" ]; then \
            filename=$(basename "$cert" .crt); \
            # Tentar converter DER para PEM (se já for PEM, openssl ignora o erro); \
            openssl x509 -inform DER -in "$cert" -out "/usr/local/share/ca-certificates/$filename.crt" 2>/dev/null || \
            openssl x509 -inform PEM -in "$cert" -out "/usr/local/share/ca-certificates/$filename.crt" 2>/dev/null || \
            cp "$cert" "/usr/local/share/ca-certificates/$filename.crt"; \
        fi; \
    done && \
    update-ca-certificates && \
    echo "Certificados do sistema atualizados."

# Criar diretório de uploads
RUN mkdir -p uploads

# Expor porta
EXPOSE 3000

# Comando para iniciar
CMD ["npm", "start"]
