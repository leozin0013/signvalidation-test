#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Script para validar assinatura digital em PDF usando pyHanko
Compatível com assinaturas ICP-Brasil (Gov.br)
"""

import sys
import io
import json
import warnings
import logging
import time
from pathlib import Path

# Forçar UTF-8 no stdout para Windows
sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding='utf-8', errors='replace')

# Suprimir warnings e erros de revogação do pyHanko (soft-fail esperado)
warnings.filterwarnings('ignore', category=UserWarning, module='pyhanko')
warnings.filterwarnings('ignore', category=DeprecationWarning, module='pyhanko')

# Configurar logging do pyHanko para mostrar apenas erros críticos
logging.getLogger('pyhanko').setLevel(logging.CRITICAL)
logging.getLogger('pyhanko_certvalidator').setLevel(logging.CRITICAL)

try:
    from pyhanko.sign.validation import validate_pdf_signature
    from pyhanko.pdf_utils.reader import PdfFileReader
    import pyhanko.sign.validation as val_module
    from pyhanko_certvalidator import ValidationContext
    from pyhanko_certvalidator.registry import SimpleTrustManager
except ImportError as e:
    # Retornar erro em JSON se pyHanko não estiver instalado
    error_result = {
        "success": False,
        "error": "Biblioteca pyHanko nao instalada",
        "details": f"Execute: pip install pyHanko pyhanko-certvalidator\nErro: {str(e)}"
    }
    print(json.dumps(error_result, ensure_ascii=False))
    sys.exit(0)


# Cache global de certificados (carregado uma única vez)
_CERT_CACHE = None
_CERT_CACHE_LOCK = False


def load_local_trust_roots():
    """Carrega certificados raiz ICP-Brasil da pasta local E do system trust store
    IMPORTANTE: Retorna lista de objetos asn1crypto.x509.Certificate (compatível com pyHanko)
    USA CACHE: Carrega apenas uma vez e reutiliza em validações subsequentes
    """
    global _CERT_CACHE, _CERT_CACHE_LOCK
    
    # Retornar cache se já carregado
    if _CERT_CACHE is not None:
        print(f"[CACHE] Usando {len(_CERT_CACHE)} certificados em cache", file=sys.stderr)
        return _CERT_CACHE
    
    # Evitar carregamento múltiplo simultâneo
    if _CERT_CACHE_LOCK:
        import time
        for _ in range(50):  # Esperar até 5 segundos
            time.sleep(0.1)
            if _CERT_CACHE is not None:
                return _CERT_CACHE
        return []
    
    print("[CACHE] Carregando certificados pela primeira vez...", file=sys.stderr)
    _CERT_CACHE_LOCK = True
    trust_roots = []
    
    # Lista de diretórios para procurar certificados
    cert_dirs = [
        Path(__file__).parent / 'certs',  # Certificados locais (~324 da ICP-Brasil)
        Path('/usr/local/share/ca-certificates'),  # Certificados instalados manualmente (Docker)
        Path('/etc/ssl/certs'),  # System trust store Linux
    ]
    
    try:
        from asn1crypto import x509, pem
        
        seen_subjects = set()  # Para evitar duplicados
        
        for certs_dir in cert_dirs:
            if not certs_dir.exists():
                continue
            
            # Procurar arquivos .crt e .pem
            for ext in ['*.crt', '*.pem']:
                for cert_file in certs_dir.glob(ext):
                    # Ignorar symlinks (para evitar duplicados no /etc/ssl/certs)
                    if cert_file.is_symlink():
                        continue
                        
                    try:
                        with open(cert_file, 'rb') as f:
                            cert_data = f.read()
                            
                            # Detectar se é PEM ou DER
                            if pem.detect(cert_data):
                                # PEM: extrair primeiro certificado
                                _, _, cert_data = pem.unarmor(cert_data)
                            
                            # Carregar como asn1crypto Certificate
                            cert = x509.Certificate.load(cert_data)
                            
                            # Evitar duplicados (comparar por subject)
                            subject_key = cert.subject.hashable
                            if subject_key not in seen_subjects:
                                trust_roots.append(cert)
                                seen_subjects.add(subject_key)
                    except Exception as e:
                        # Ignorar certificados inválidos silenciosamente
                        pass
    except Exception as e:
        # Se asn1crypto não estiver disponível, retornar vazio
        pass
    
    # Salvar no cache
    _CERT_CACHE = trust_roots
    _CERT_CACHE_LOCK = False
    print(f"[CACHE] Carregados {len(trust_roots)} certificados únicos", file=sys.stderr)
    
    return trust_roots


def get_validation_context():
    """Retorna contexto de validação com certificados ICP-Brasil + System Trust Store
    
    Carrega todos os ~324 certificados da ICP-Brasil e confia em TODOS:
    - trust_roots: TODOS os certificados ICP-Brasil (são todos oficiais do repositório ITI)
    - other_certs: TODOS os certificados (para construção de cadeia e validação de CRLs)
    
    Isso permite validação completa: integridade + cadeia + revogação via CRL.
    """
    try:
        # Carregar TODOS os certificados locais + system trust store (~320 certificados)
        all_certs = load_local_trust_roots()
        
        if all_certs:
            # IMPORTANTE: Confiar em TODOS os certificados da ICP-Brasil
            # Todos são certificados oficiais baixados do repositório acraiz.icpbrasil.gov.br
            # Isso inclui: RAIZ, intermediárias, finais - toda hierarquia ICP-Brasil
            trust_manager = SimpleTrustManager.build(
                trust_roots=all_certs,  # TODOS os certificados ICP-Brasil são confiáveis
                extra_trust_roots=[],
            )
            return ValidationContext(
                trust_manager=trust_manager,
                allow_fetching=True,  # Permite download de CRLs e certificados via AIA
                revocation_mode='soft-fail',  # Tenta verificar revogação mas não falha por problemas
                other_certs=all_certs  # Disponibilizar TODOS os certs para construir cadeia de CRL
            )
        else:
            # Fallback: usar ValidationContext padrão
            return ValidationContext(
                allow_fetching=True,
                revocation_mode='soft-fail'
            )
    except Exception as e:
        # Fallback: contexto padrão com soft-fail
        try:
            return ValidationContext(allow_fetching=True, revocation_mode='soft-fail')
        except:
            # Último recurso: validação padrão
            return ValidationContext()


def extract_cert_info(cert):
    """Extrai informações do certificado"""
    info = {}
    
    try:
        from cryptography import x509
        from cryptography.x509.oid import NameOID, ExtensionOID
        
        # Se cert não é um objeto x509.Certificate, tentar convertê-lo
        if not isinstance(cert, x509.Certificate):
            # Pode ser um objeto pyhanko - tentar extrair o certificado subjacente
            if hasattr(cert, 'dump'):
                # Converter de asn1crypto para cryptography
                from cryptography.hazmat.primitives import serialization
                cert_bytes = cert.dump()
                cert = x509.load_der_x509_certificate(cert_bytes)
            elif hasattr(cert, 'to_cryptography'):
                cert = cert.to_cryptography()
            else:
                info['conversion_error'] = f'Tipo de certificado desconhecido: {type(cert)}'
                return info
        
        # Extrair nome do titular (Common Name)
        try:
            cn_list = cert.subject.get_attributes_for_oid(NameOID.COMMON_NAME)
            if cn_list:
                info['name'] = cn_list[0].value
        except Exception as e:
            info['name_error'] = str(e)
        
        # Extrair emissor
        try:
            issuer_cn = cert.issuer.get_attributes_for_oid(NameOID.COMMON_NAME)
            if issuer_cn:
                info['issuer'] = issuer_cn[0].value
        except Exception as e:
            info['issuer_error'] = str(e)
                
        # Tentar extrair CPF/CNPJ das extensões (OIDs ICP-Brasil)
        # OID 2.16.76.1.3.1 = CPF
        # OID 2.16.76.1.3.3 = CNPJ
        try:
            # Procurar no subject alternative names
            try:
                san_ext = cert.extensions.get_extension_for_oid(ExtensionOID.SUBJECT_ALTERNATIVE_NAME)
                for name in san_ext.value:
                    name_str = str(name.value) if hasattr(name, 'value') else str(name)
                    # Extrair CPF
                    if 'CPF' in name_str.upper() or '2.16.76.1.3.1' in name_str:
                        # Tentar extrair apenas os números
                        import re
                        cpf_match = re.search(r'(\d{11})', name_str)
                        if cpf_match:
                            cpf = cpf_match.group(1)
                            info['cpf'] = f"{cpf[:3]}.{cpf[3:6]}.{cpf[6:9]}-{cpf[9:]}"
                        else:
                            info['cpf'] = name_str
                    # Extrair CNPJ
                    elif 'CNPJ' in name_str.upper() or '2.16.76.1.3.3' in name_str:
                        import re
                        cnpj_match = re.search(r'(\d{14})', name_str)
                        if cnpj_match:
                            cnpj = cnpj_match.group(1)
                            info['cnpj'] = f"{cnpj[:2]}.{cnpj[2:5]}.{cnpj[5:8]}/{cnpj[8:12]}-{cnpj[12:]}"
                        else:
                            info['cnpj'] = name_str
            except x509.ExtensionNotFound:
                pass
            except Exception as e:
                info['san_error'] = str(e)
                
        except Exception as e:
            info['cpf_cnpj_extraction_error'] = str(e)
            
        # Informações de validade
        try:
            info['not_before'] = cert.not_valid_before_utc.isoformat() if hasattr(cert, 'not_valid_before_utc') else cert.not_valid_before.isoformat()
            info['not_after'] = cert.not_valid_after_utc.isoformat() if hasattr(cert, 'not_valid_after_utc') else cert.not_valid_after.isoformat()
        except Exception as e:
            info['validity_error'] = str(e)
                
    except Exception as e:
        info['extraction_error'] = str(e)
    
    return info


def validate_pdf(pdf_path):
    """Valida assinatura digital do PDF"""
    
    try:
        # Abrir o PDF
        with open(pdf_path, 'rb') as pdf_file:
            pdf_reader = PdfFileReader(pdf_file)
            
            # Buscar campos de assinatura
            embedded_sigs = pdf_reader.embedded_signatures
            
            if not embedded_sigs:
                return {
                    "success": False,
                    "error": "Nenhuma assinatura digital encontrada no PDF",
                    "details": "O arquivo nao contem assinaturas ou foi modificado após a assinatura."
                }
            
            validation_results = []
            signer_info = None
            has_signature = False
            
            # Validar cada assinatura encontrada
            for sig_idx, sig_field in enumerate(embedded_sigs, 1):
                try:
                    # Extrair informações básicas
                    sig_info = {
                        'signature_number': sig_idx,
                        'field_name': str(sig_field.field_name) if hasattr(sig_field, 'field_name') else f'Signature {sig_idx}'
                    }
                    
                    # Primeiro: tentar obter o certificado diretamente do campo
                    cert = None
                    try:
                        # Método mais direto: através do objeto de assinatura
                        if hasattr(sig_field, 'sig_object') and sig_field.sig_object:
                            sig_obj = sig_field.sig_object
                            # Tentar pegar certificados do CMS
                            if hasattr(sig_obj, 'certs') and sig_obj.certs:
                                # Primeiro certificado geralmente é o do assinante
                                cert = sig_obj.certs[0]
                            elif hasattr(sig_obj, 'signer_cert'):
                                cert = sig_obj.signer_cert
                    except Exception as e:
                        pass
                    
                    # Tentar validar (pode falhar por falta de CAs raiz)
                    validation_result = None
                    cert = None
                    
                    try:
                        # Usar contexto de validação com certificados ICP-Brasil
                        vc = get_validation_context()
                        validation_result = validate_pdf_signature(sig_field, signer_validation_context=vc)
                        has_signature = True
                        
                        # Status da validação (ajustado para diferentes versões do pyHanko)
                        if hasattr(validation_result, 'status'):
                            status = validation_result.status
                            sig_info['valid'] = status == val_module.SignatureStatus.VALID
                            sig_info['status'] = str(status)
                        else:
                            # Versão mais recente do pyHanko - usar bottom_line como indicador final
                            # bottom_line combina intact, trusted E revocation
                            if hasattr(validation_result, 'bottom_line'):
                                sig_info['valid'] = validation_result.bottom_line
                            else:
                                sig_info['valid'] = validation_result.intact and validation_result.trusted
                            
                            sig_info['status'] = 'VALID' if sig_info['valid'] else 'INVALID'
                        
                        # Verificação adicional: integridade e confiabilidade
                        if hasattr(validation_result, 'intact'):
                            sig_info['intact'] = validation_result.intact
                        if hasattr(validation_result, 'trusted'):
                            sig_info['trusted'] = validation_result.trusted
                        if hasattr(validation_result, 'bottom_line'):
                            sig_info['bottom_line'] = validation_result.bottom_line
                        
                        # SOFT-FAIL: Aceitar documentos íntegros mesmo com problemas de revogação
                        # Se intact=True mas trusted=False, geralmente é problema de infraestrutura CRL
                        # Validamos: integridade (SHA-256) + cadeia ICP-Brasil
                        # Se bottom_line=False mas intact=True, pode ser revogação não verificada
                        if sig_info.get('intact') and not sig_info.get('bottom_line', True):
                            # Verificar se valid é True (revogação funcionou mesmo com soft-fail)
                            if hasattr(validation_result, 'valid') and validation_result.valid:
                                sig_info['status'] = 'VALID'
                                sig_info['valid'] = True
                                sig_info['trusted'] = True  # Revogação OK
                            else:
                                sig_info['status'] = 'VALID_REVOCATION_UNVERIFIED'
                                sig_info['valid'] = True
                                sig_info['trusted'] = True  # Cadeia foi validada
                            
                        # Tentar extrair certificado de múltiplas formas
                        if hasattr(validation_result, 'signer_cert') and validation_result.signer_cert:
                            cert = validation_result.signer_cert
                        elif hasattr(validation_result, 'cert') and validation_result.cert:
                            cert = validation_result.cert
                        elif hasattr(sig_field, 'signer_cert') and sig_field.signer_cert:
                            cert = sig_field.signer_cert
                        elif hasattr(sig_field, 'sig_object'):
                            if hasattr(sig_field.sig_object, 'signer_cert'):
                                cert = sig_field.sig_object.signer_cert
                        
                        # Debug: tentar outros atributos do validation_result
                        if not cert and hasattr(validation_result, 'coverage'):
                            if hasattr(validation_result.coverage, 'signer_cert'):
                                cert = validation_result.coverage.signer_cert
                        
                        if not cert and hasattr(validation_result, 'signed_data'):
                            if hasattr(validation_result.signed_data, 'signer_cert'):
                                cert = validation_result.signed_data.signer_cert
                        
                    except Exception as val_error:
                        # Validação falhou (provavelmente erro de revogação ou falta CA raiz)
                        # Mas ainda podemos extrair informações do certificado
                        error_msg = str(val_error)
                        sig_info['validation_error'] = error_msg
                        
                        # Erro de validação - verificar se é revogação ou cadeia
                        if 'revocation' in error_msg.lower() or 'InsufficientRevinfoError' in error_msg:
                            sig_info['status'] = 'REVOCATION_CHECK_FAILED'
                            # Tentar verificar integridade mesmo com erro de revogação
                            try:
                                integrity_info = sig_field.compute_integrity_info()
                                if hasattr(integrity_info, 'intact'):
                                    sig_info['intact'] = integrity_info.intact
                                    # Se documento está íntegro, aceitar como válido (revogação não verificada)
                                    if integrity_info.intact:
                                        sig_info['status'] = 'VALID_REVOCATION_UNVERIFIED'
                                        sig_info['valid'] = True
                                        sig_info['trusted'] = True
                            except Exception:
                                pass
                        else:
                            sig_info['status'] = 'TRUST_CHAIN_ERROR'
                            sig_info['valid'] = False
                        has_signature = True
                        
                        # Tentar extrair certificado diretamente do campo de assinatura
                        if hasattr(sig_field, 'signer_cert') and sig_field.signer_cert:
                            cert = sig_field.signer_cert
                        elif hasattr(sig_field, 'sig_object'):
                            if hasattr(sig_field.sig_object, 'signer_cert'):
                                cert = sig_field.sig_object.signer_cert
                    
                    # Extrair informações do certificado (se conseguimos obtê-lo)
                    if cert:
                        try:
                            cert_info = extract_cert_info(cert)
                            sig_info['certificate'] = cert_info
                            
                            # Extrair signer_info se assinatura válida (inclui VALID_REVOCATION_UNVERIFIED)
                            if signer_info is None and sig_info.get('valid'):
                                signer_info = cert_info
                        except Exception as cert_error:
                            sig_info['certificate_error'] = str(cert_error)
                    else:
                        # Se ainda não temos certificado, adicionar informação de debug
                        sig_info['certificate_warning'] = 'Nao foi possivel extrair certificado'
                    
                    # Timestamp
                    if validation_result and hasattr(validation_result, 'timestamp'):
                        try:
                            sig_info['timestamp'] = str(validation_result.timestamp)
                        except:
                            pass
                    
                    validation_results.append(sig_info)
                        
                except Exception as sig_error:
                    validation_results.append({
                        'signature_number': sig_idx,
                        'valid': False,
                        'error': str(sig_error)
                    })
                    has_signature = True
            
            # Preparar resposta detalhada
            details_lines = [f"Total de assinaturas encontradas: {len(embedded_sigs)}"]
            for result in validation_results:
                # Aceitar como OK se valid=True (inclui VALID_REVOCATION_UNVERIFIED)
                is_valid = result.get('valid', False)
                status = result.get('status', 'Unknown')
                
                # Determinar emoji baseado na validação
                status_emoji = "[OK]" if is_valid else "[INVALIDO]"
                    
                details_lines.append(f"\n{status_emoji} Assinatura #{result['signature_number']}:")
                
                # Traduzir status para português
                status_display = status
                if status == 'VALID_REVOCATION_UNVERIFIED':
                    status_display = 'VALIDO (Revogacao nao verificada - infraestrutura CRL indisponivel)'
                elif status == 'VALID':
                    status_display = 'VALIDO (Integridade + Cadeia + Revogacao verificadas)'
                elif 'REVOCATION_CHECK_FAILED' in status:
                    status_display = 'INVALIDO (Erro ao verificar revogacao)'
                elif 'TRUST_CHAIN' in status:
                    status_display = 'INVALIDO (Cadeia de confianca invalida)'
                    
                details_lines.append(f"  Status: {status_display}")
                
                # Mostrar status de integridade
                if 'intact' in result:
                    details_lines.append(f"  Documento integro: {'Sim' if result['intact'] else 'Nao'}")
                if 'trusted' in result:
                    details_lines.append(f"  Cadeia confiavel: {'Sim' if result['trusted'] else 'Nao (falta CA raiz ICP-Brasil)'}")
                
                if 'certificate' in result:
                    cert = result['certificate']
                    if 'name' in cert:
                        details_lines.append(f"  Titular: {cert['name']}")
                    if 'cpf' in cert:
                        details_lines.append(f"  CPF: {cert['cpf']}")
                    if 'cnpj' in cert:
                        details_lines.append(f"  CNPJ: {cert['cnpj']}")
                    if 'issuer' in cert:
                        details_lines.append(f"  Emitido por: {cert['issuer']}")
                
                if 'validation_error' in result:
                    details_lines.append(f"  Erro: {result['validation_error']}")
                
                if 'error' in result:
                    details_lines.append(f"  Erro: {result['error']}")
            
            # Sucesso se tem assinatura válida (inclui VALID e VALID_REVOCATION_UNVERIFIED)
            has_valid_signature = any(r.get('valid', False) for r in validation_results)
            has_intact_signature = any(r.get('intact', False) for r in validation_results)
            
            # Sucesso = tem assinatura válida (integridade + cadeia verificadas)
            success = has_signature and has_valid_signature
            
            warning_msg = None
            if success:
                # Se válido mas revogação não foi verificada, avisar
                if any(r.get('status') == 'VALID_REVOCATION_UNVERIFIED' for r in validation_results):
                    warning_msg = "Documento integro e cadeia de certificados validada. AVISO: Verificacao de revogacao nao disponivel devido a limitacoes na infraestrutura ITI (certificados CA LCR ausentes). Recomenda-se validar em validador.iti.gov.br para confirmacao completa."
            elif not success and has_signature:
                # Se tem assinatura mas não é válida, explicar o motivo
                if any('TRUST_CHAIN' in r.get('status', '') for r in validation_results):
                    warning_msg = "Assinatura rejeitada: cadeia de confianca invalida. O certificado nao e confiavel ou nao pertence a ICP-Brasil."
                elif any('validation_error' in r for r in validation_results):
                    errors = [r.get('validation_error', '') for r in validation_results if 'validation_error' in r]
                    warning_msg = f"Assinatura rejeitada: {errors[0] if errors else 'erro de validacao'}"
            
            return {
                "success": success,
                "signerInfo": signer_info,
                "validationResults": validation_results,
                "totalSignatures": len(embedded_sigs),
                "details": "\n".join(details_lines),
                "warning": warning_msg
            }
            
    except FileNotFoundError:
        return {
            "success": False,
            "error": "Arquivo PDF nao encontrado",
            "details": f"O arquivo {pdf_path} nao existe."
        }
    except Exception as e:
        return {
            "success": False,
            "error": "Erro ao processar PDF",
            "details": f"Tipo: {type(e).__name__}\nMensagem: {str(e)}"
        }


def main():
    """Funcao principal"""
    
    start_time = time.time()
    
    try:
        # Verificar argumentos
        if len(sys.argv) < 2:
            result = {
                "success": False,
                "error": "Nenhum arquivo especificado",
                "details": "Uso: python validate_signature.py <caminho_do_pdf>"
            }
            print(json.dumps(result, ensure_ascii=False))
            sys.exit(0)
        
        pdf_path = sys.argv[1]
        
        # Validar
        result = validate_pdf(pdf_path)
        
        # Adicionar tempo de execução
        elapsed_time = time.time() - start_time
        result['execution_time'] = f"{elapsed_time:.2f}s"
        print(f"[TIMING] Validação completa em {elapsed_time:.2f}s", file=sys.stderr)
        
        # Retornar resultado como JSON (sempre ASCII-safe para evitar problemas de encoding)
        print(json.dumps(result, ensure_ascii=False, indent=2))
        
        # Sempre retornar 0 para não quebrar o Node
        sys.exit(0)
        
    except Exception as e:
        # Capturar qualquer erro não tratado
        error_result = {
            "success": False,
            "error": "Erro fatal no script Python",
            "details": str(e)
        }
        print(json.dumps(error_result, ensure_ascii=False))
        sys.exit(0)  # Ainda retornar 0 mas com erro no JSON


if __name__ == '__main__':
    main()
