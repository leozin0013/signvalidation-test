#!/usr/bin/env python3
"""Script para inspecionar URLs de CRL e OCSP em certificado do PDF"""

import sys
from pathlib import Path
from pyhanko.pdf_utils.reader import PdfFileReader
from cryptography import x509
from cryptography.x509.oid import ExtensionOID

# Procurar PDF na pasta uploads
uploads_dir = Path(__file__).parent / 'uploads'
pdf_files = list(uploads_dir.glob('*.pdf'))

if not pdf_files:
    print("Nenhum PDF encontrado em uploads/")
    sys.exit(1)

pdf_path = pdf_files[0]
print(f"Analisando: {pdf_path.name}\n")

with open(pdf_path, 'rb') as f:
    reader = PdfFileReader(f)
    sigs = reader.embedded_signatures
    
    if not sigs:
        print("Nenhuma assinatura encontrada")
        sys.exit(1)
    
    sig = sigs[0]
    
    # Pegar certificado
    cert = sig.signer_cert
    if hasattr(cert, 'dump'):
        cert_bytes = cert.dump()
        cert = x509.load_der_x509_certificate(cert_bytes)
    
    print(f"Certificado: {cert.subject.rfc4514_string()}\n")
    
    # CRL Distribution Points
    try:
        crl_ext = cert.extensions.get_extension_for_oid(ExtensionOID.CRL_DISTRIBUTION_POINTS)
        print("CRL Distribution Points:")
        for dp in crl_ext.value:
            if dp.full_name:
                for name in dp.full_name:
                    print(f"  {name.value}")
        print()
    except x509.ExtensionNotFound:
        print("Sem CRL Distribution Points\n")
    
    # Authority Information Access (OCSP)
    try:
        aia_ext = cert.extensions.get_extension_for_oid(ExtensionOID.AUTHORITY_INFORMATION_ACCESS)
        print("Authority Information Access:")
        for desc in aia_ext.value:
            print(f"  {desc.access_method._name}: {desc.access_location.value}")
        print()
    except x509.ExtensionNotFound:
        print("Sem AIA\n")
    
    # Issuer
    print(f"Emissor: {cert.issuer.rfc4514_string()}")
