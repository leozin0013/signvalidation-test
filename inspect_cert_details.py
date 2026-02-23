#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Script para inspecionar TODOS os campos de um certificado em PDF
"""

import sys
from pathlib import Path
from pyhanko.pdf_utils.reader import PdfFileReader
from cryptography import x509
from cryptography.x509.oid import NameOID, ExtensionOID

def inspect_certificate(pdf_path):
    """Inspeciona certificado de um PDF assinado"""
    
    if not Path(pdf_path).exists():
        print(f"Arquivo não encontrado: {pdf_path}")
        return
    
    with open(pdf_path, 'rb') as f:
        reader = PdfFileReader(f)
        
        if not reader.embedded_signatures:
            print("PDF não possui assinaturas")
            return
        
        # Pegar primeira assinatura
        sig = reader.embedded_signatures[0]
        
        # Converter certificado para cryptography
        cert_bytes = sig.signer_cert.dump()
        cert = x509.load_der_x509_certificate(cert_bytes)
        
        print("=" * 80)
        print("SUBJECT (DN - Distinguished Name)")
        print("=" * 80)
        for attr in cert.subject:
            print(f"{attr.oid.dotted_string:30} ({attr.oid._name:30}): {attr.value}")
        
        print("\n" + "=" * 80)
        print("ISSUER")
        print("=" * 80)
        for attr in cert.issuer:
            print(f"{attr.oid.dotted_string:30} ({attr.oid._name:30}): {attr.value}")
        
        print("\n" + "=" * 80)
        print("EXTENSIONS (Extensões do certificado)")
        print("=" * 80)
        
        for ext in cert.extensions:
            print(f"\n--- Extension: {ext.oid.dotted_string} ({ext.oid._name}) ---")
            print(f"Critical: {ext.critical}")
            
            # Subject Alternative Name (onde CPF geralmente está)
            if ext.oid == ExtensionOID.SUBJECT_ALTERNATIVE_NAME:
                print("SUBJECT ALTERNATIVE NAME:")
                for name in ext.value:
                    print(f"  Type: {type(name).__name__}")
                    print(f"  Value: {name.value if hasattr(name, 'value') else name}")
                    
                    # Tentar decodificar se for OtherName (CPF/CNPJ ICP-Brasil)
                    if hasattr(name, 'type_id'):
                        print(f"  Type ID (OID): {name.type_id.dotted_string}")
                        
                        # OIDs ICP-Brasil
                        if '2.16.76.1.3' in name.type_id.dotted_string:
                            print(f"  >>> ICP-Brasil Field Detected! <<<")
                            print(f"  Raw Value (bytes): {name.value if hasattr(name, 'value') else 'N/A'}")
            else:
                # Outras extensões
                try:
                    print(f"Value: {ext.value}")
                except:
                    print("Value: <binary data>")
        
        print("\n" + "=" * 80)
        print("OUTRAS INFORMAÇÕES")
        print("=" * 80)
        print(f"Serial Number: {hex(cert.serial_number)[2:].upper()}")
        print(f"Not Before: {cert.not_valid_before_utc}")
        print(f"Not After: {cert.not_valid_after_utc}")
        print(f"Fingerprint SHA256: {cert.fingerprint(cert.hash_algorithm).hex().upper()}")
        

if __name__ == '__main__':
    if len(sys.argv) < 2:
        print("Uso: python inspect_cert_details.py <caminho_do_pdf>")
        sys.exit(1)
    
    inspect_certificate(sys.argv[1])
