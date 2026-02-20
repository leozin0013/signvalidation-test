#!/usr/bin/env python3
"""Teste de validação com modo hard-fail para forçar verificação completa de revogação"""

import sys
import logging
from pathlib import Path

# Ativar logs INFO (não DEBUG pois fica muito verboso)
logging.basicConfig(
    level=logging.INFO,
    format='%(levelname)s: %(message)s'
)

# Ativar logs do pyHanko
logging.getLogger('pyhanko').setLevel(logging.INFO)
logging.getLogger('pyhanko_certvalidator').setLevel(logging.WARNING)

from pyhanko.sign.validation import validate_pdf_signature
from pyhanko.pdf_utils.reader import PdfFileReader
from pyhanko_certvalidator import ValidationContext

# PDF de teste
pdf_path = Path(__file__).parent / 'uploads' / 'Contrato_Leonardo_Moreto_Azambuja_1771520339017_assinado - Copia.pdf'

print("=" * 80)
print("TESTE: VALIDAÇÃO COM REVOCATION_MODE='hard-fail'")
print("=" * 80)
print(f"PDF: {pdf_path.name}\n")
print("[INFO] Certificados em certs/:", len(list((Path(__file__).parent / 'certs').glob('*.crt'))), "arquivos CRT")
print("[INFO] Certificados em certs/:", len(list((Path(__file__).parent / 'certs').glob('*.cer'))), "arquivos CER")
print()

# Testar com diferentes modos de revogação
for mode in ['soft-fail', 'hard-fail', 'require']:
    print(f"\n{'='*80}")
    print(f"TESTE COM revocation_mode='{mode}'")
    print('='*80)
    
    try:
        # Criar contexto com allow_fetching permitindo download de CRLs e certificados via AIA
        vc = ValidationContext(
            allow_fetching=True,
            revocation_mode=mode
        )
        
        print(f"[OK] Contexto criado: allow_fetching=True, revocation_mode='{mode}'")
        
        # Validar
        with open(pdf_path, 'rb') as f:
            reader = PdfFileReader(f)
            sig = reader.embedded_signatures[0]
            
            print("[INFO] Validando assinatura...")
            status = validate_pdf_signature(sig, vc)
            
            print("\nRESULTADO:")
            print(f"  Valid: {status.valid}")
            print(f"  Intact: {status.intact}")
            print(f"  Trusted: {status.trusted}")
            print(f"  Coverage: {status.coverage}")
            print(f"  Revocation: {status.revocation_validation_status}")
            
            if status.valid:
                print(f"\n  ✓ SUCESSO com modo '{mode}'!")
            else:
                print(f"\n  ✗ FALHOU com modo '{mode}'")
                
    except Exception as e:
        print(f"\n  ✗ ERRO com modo '{mode}': {type(e).__name__}: {str(e)[:200]}")

print("\n" + "=" * 80)
print("CONCLUSÃO")
print("=" * 80)
print("Se 'hard-fail' ou 'require' passaram, a validação de revogação está funcionando!")
print("Se apenas 'soft-fail' passou, ainda há problemas com CRL.")
print("=" * 80)
