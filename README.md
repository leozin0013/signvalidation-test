# Validador de Assinatura Digital ICP-Brasil

Sistema para validação de assinaturas digitais em documentos PDF assinados com certificados ICP-Brasil (Gov.br).

## Funcionalidades

### O que valida

- **Integridade do documento**: Verifica se o PDF foi alterado após a assinatura (hash SHA-256)
- **Cadeia de certificados**: Valida se o certificado pertence à hierarquia ICP-Brasil/Gov.br
- **Validade temporal**: Confirma se o certificado está dentro do período de validade
- **Extração de dados**: Nome do assinante, CPF/CNPJ, emissor do certificado

### Limitações conhecidas

- **Validação de revogação**: Não funciona completamente devido a limitações na infraestrutura de CRL (Certificate Revocation List) do ITI
- Certificados CA LCR (que assinam as CRLs) não estão disponíveis publicamente no repositório ITI
- O sistema usa modo `soft-fail` para revogação: tenta verificar mas não falha se houver problemas

## Arquitetura

- **Frontend**: HTML5, CSS3, JavaScript Vanilla
- **Backend**: Node.js + TypeScript + Express
- **Validação**: Python 3.11 + pyHanko
- **Deploy**: Docker (node:18-slim)

## Pré-requisitos

### Execução Local

- Node.js 18+
- Python 3.11+
- npm ou yarn

### Execução Docker

- Docker Desktop

## Instalação e Execução

### Opção 1: Localhost (Desenvolvimento)

#### Backend

```bash
cd sign-backend

# Instalar dependências Node.js
npm install

# Instalar dependências Python
pip install -r requirements.txt

# Executar em modo desenvolvimento
npm run dev
```

O servidor estará disponível em `http://localhost:3000`

#### Frontend

```bash
cd sign-frontend

# Servir com servidor HTTP simples
python -m http.server 8080
```

Acesse `http://localhost:8080` no navegador.

### Opção 2: Docker (Recomendado)

```bash
cd sign-backend

# Build da imagem
docker build -t pdf-signature-validator .

# Executar container
docker run -d --name validator -p 3000:3000 pdf-signature-validator

# Ver logs
docker logs -f validator

# Parar container
docker stop validator
docker rm validator
```

**Vantagens do Docker:**
- Certificados ICP-Brasil são baixados e instalados automaticamente
- Ambiente isolado e reproduzível
- Pronto para deploy em produção

## Scripts Python Auxiliares

### validate_signature.py

Script principal que realiza a validação de assinaturas digitais.

**Uso:**
```bash
python validate_signature.py <caminho-do-pdf>
```

**Saída:** JSON com resultado da validação

**Funcionalidades:**
- Carrega certificados ICP-Brasil de múltiplas fontes (`/app/certs/`, `/etc/ssl/certs/`, `/usr/local/share/ca-certificates/`)
- Valida integridade do documento usando pyHanko
- Valida cadeia de certificados
- Tenta validar revogação (soft-fail)
- Extrai informações do assinante (nome, CPF/CNPJ)

### inspect_crl.py

Ferramenta de debug para inspecionar CRLs (Certificate Revocation Lists).

**Uso:**
```bash
python inspect_crl.py [url-da-crl]
```

**O que faz:**
- Baixa CRL de uma URL
- Mostra quem assinou a CRL (issuer)
- Lista certificados revogados
- Ajuda a identificar certificados CA LCR necessários

### inspect_pdf_cert.py

Analisa certificados embutidos em um PDF assinado.

**Uso:**
```bash
python inspect_pdf_cert.py
```

**O que faz:**
- Procura PDFs na pasta `uploads/`
- Extrai certificado do assinante
- Mostra URLs de CRL e OCSP
- Lista informações do emissor

## API Backend

### POST /validate

Valida assinatura digital de um PDF.

**Request:**
```
Content-Type: multipart/form-data
pdf: <arquivo.pdf>
```

**Response (Sucesso):**
```json
{
  "success": true,
  "signerInfo": {
    "name": "NOME DO ASSINANTE",
    "issuer": "AC Final do Governo Federal do Brasil v1",
    "cpf": "123.456.789-10",
    "not_before": "2025-11-13T00:33:09+00:00",
    "not_after": "2026-11-13T00:33:09+00:00"
  },
  "validationResults": [
    {
      "signature_number": 1,
      "valid": true,
      "status": "VALID_REVOCATION_UNVERIFIED",
      "intact": true,
      "trusted": true
    }
  ],
  "totalSignatures": 1,
  "warning": "Documento integro e cadeia de certificados validada..."
}
```

**Response (Erro):**
```json
{
  "success": false,
  "error": "Nenhuma assinatura digital encontrada no PDF",
  "details": "O arquivo nao contem assinaturas digitais..."
}
```

## Certificados

O sistema carrega automaticamente certificados de:

### ICP-Brasil RAIZ
- ICP-Brasil v2, v5, v10, v11, v12, v13

### Gov.br (Cadeia Completa)
- Autoridade Certificadora Raiz do Governo Federal do Brasil v1
- AC Intermediária do Governo Federal do Brasil v1
- AC Final do Governo Federal do Brasil v1

### Origem dos Certificados

- **ICP-Brasil**: `http://acraiz.icpbrasil.gov.br/credenciadas/RAIZ/`
- **Gov.br**: `http://repo.iti.br/docs/Cadeia_GovBr-der.p7b`

## Validação de Revogação

### Por que não funciona completamente?

A CRL (Certificate Revocation List) é baixada com sucesso, mas:

1. A CRL é assinada por um certificado "CA LCR"
2. Este certificado CA LCR não está disponível publicamente no repositório ITI
3. pyHanko rejeita a CRL porque não pode validar sua assinatura

### Impacto

- **Validado**: Integridade do documento + Cadeia de certificados + Validade temporal
- **Não validado**: Status de revogação do certificado
- **Status retornado**: `VALID_REVOCATION_UNVERIFIED`

### Mitigação

Para validação completa de revogação, use:
- Validador oficial: https://validador.iti.gov.br
- OCSP (se disponível no certificado)
- Serviço de API do ITI

## Caso de Uso Recomendado

Este validador é adequado para:

- Sistemas de matrícula/cadastro
- Validação de contratos digitais
- Verificação de autenticidade de documentos
- Casos onde revogação não é crítica

**Não recomendado para:**
- Documentos judiciais críticos
- Transações financeiras de alto valor
- Casos onde validação de revogação é obrigatória

## Build Docker

O Dockerfile realiza automaticamente:

1. Instalação de Node.js e Python
2. Download de certificados ICP-Brasil RAIZ
3. Download e extração da cadeia Gov.br
4. Instalação de certificados no system trust store Linux
5. Compilação do TypeScript
6. Configuração do servidor Express

## Configuração

### Backend URL (Frontend)

Edite `sign-frontend/index.html`:

```javascript
const BACKEND_URL = 'http://localhost:3000';  // Localhost
// const BACKEND_URL = 'https://seu-app.onrender.com';  // Produção
```

### Porta do Servidor (Backend)

Use variável de ambiente:

```bash
PORT=3001 npm run dev
```

Ou edite `src/server.ts`:

```typescript
const PORT = process.env.PORT || 3000;
```

## Desenvolvimento

### Adicionar logs de debug

No `validate_signature.py`, remova supressão de logs:

```python
# Comentar estas linhas:
# logging.getLogger('pyhanko').setLevel(logging.CRITICAL)
# logging.getLogger('pyhanko_certvalidator').setLevel(logging.CRITICAL)
```

### Testar validação localmente

```bash
# Colocar PDF em uploads/
python validate_signature.py uploads/seu-arquivo.pdf
```

## Contribuições

Contribuições são bem-vindas. Por favor:

1. Fork o repositório
2. Crie uma branch para sua feature
3. Commit suas mudanças
4. Push para a branch
5. Abra um Pull Request

## Referências

- [pyHanko Documentation](https://pyhanko.readthedocs.io/)
- [ICP-Brasil](https://www.gov.br/iti/pt-br/assuntos/icp-brasil)
- [Validador ITI](https://validador.iti.gov.br)

---

Este repositório foi desenvolvido com auxílio da API Anthropic Claude.