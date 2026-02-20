# Validador de Assinatura Digital ICP-Brasil

Sistema para validação de assinaturas digitais em documentos PDF assinados com certificados ICP-Brasil (Gov.br).

## Funcionalidades

- **Integridade do documento**: Verifica se o PDF foi alterado após a assinatura (hash SHA-256)
- **Cadeia de certificados**: Valida se o certificado pertence à hierarquia ICP-Brasil/Gov.br
- **Validade temporal**: Confirma se o certificado está dentro do período de validade
- **Validação de revogação**: Verifica CRLs usando todos os ~324 certificados ICP-Brasil
- **Extração de dados**: Nome do assinante, CPF/CNPJ, emissor do certificado

O sistema baixa automaticamente todos os certificados da ICP-Brasil (~324 certificados) do repositório oficial, incluindo todas as Autoridades Certificadoras (ativas e expiradas) e certificados necessários para validar assinaturas de CRLs.

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

## Scripts Python

### download_all_icpbrasil_certs.py

Baixa e extrai todos os certificados ICP-Brasil do arquivo ZIP oficial (~324 certificados).

```bash
python download_all_icpbrasil_certs.py
```

### validate_signature.py

Valida assinaturas digitais em PDFs. Retorna JSON com resultado da validação (integridade, cadeia, revogação, dados do assinante).

```bash
python validate_signature.py <caminho-do-pdf>
```

### inspect_crl.py

Ferramenta de debug para inspecionar CRLs. Mostra quem assinou a CRL e lista certificados revogados.

```bash
python inspect_crl.py [url-da-crl]
```

### inspect_pdf_cert.py

Extrai e exibe informações do certificado embutido em um PDF assinado (URLs de CRL/OCSP, emissor, etc).

```bash
python inspect_pdf_cert.py
```

## API

### POST /validate

Endpoint para validação de assinaturas digitais em PDF.

**Request:**
```
Content-Type: multipart/form-data
pdf: <arquivo.pdf>
```

**Response:**
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
      "status": "VALID",
      "intact": true,
      "trusted": true
    }
  ],
  "totalSignatures": 1,
  "warning": null
}
```

## Certificados ICP-Brasil

O sistema baixa automaticamente todos os ~324 certificados da ICP-Brasil através do script `download_all_icpbrasil_certs.py`. O arquivo compactado oficial contém todas as Autoridades Certificadoras (RAIZ, intermediárias e finais), incluindo certificados ativos e expirados.

**Fonte:** `https://acraiz.icpbrasil.gov.br/credenciadas/CertificadosAC-ICP-Brasil/ACcompactadox.zip`

Durante o build Docker, os certificados são extraídos para `/app/certs/` e instalados no system trust store Linux.

## Validação de Revogação

O sistema valida revogação de certificados via CRL (Certificate Revocation List):

1. pyHanko baixa a CRL do certificado através do campo "CRL Distribution Point"
2. Valida a assinatura da CRL usando os certificados ICP-Brasil disponíveis
3. Verifica se o certificado do assinante está na lista de revogados
4. Retorna status `VALID` se o certificado não estiver revogado, ou `INVALID` se estiver

O sistema utiliza todos os ~324 certificados da ICP-Brasil para construir a cadeia de confiança necessária para validar as CRLs.

## Caso de Uso

Este validador é adequado para:

- Validação completa de assinaturas digitais ICP-Brasil
- Sistemas de matrícula/cadastro automatizado
- Validação de contratos digitais
- Verificação de autenticidade de documentos Gov.br
- Aplicações que necessitam validação de revogação
- Alternativa ao validador oficial do ITI
- Documentos judiciais, transações financeiras, processos críticos

Ideal para projetos que necessitam validação automatizada via API REST, deploy em containers Docker e validação de revogação via CRL.

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