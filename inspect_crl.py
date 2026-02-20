#!/usr/bin/env python3
"""
Script para inspecionar CRL (Certificate Revocation List)
Mostra quem assinou a CRL e quais certificados precisamos
"""

import sys
from pathlib import Path
import urllib.request

def inspect_crl(crl_url):
    """Baixa e inspeciona CRL para identificar o issuer"""
    print(f"Baixando CRL de: {crl_url}\n")
    
    try:
        # Baixar CRL
        with urllib.request.urlopen(crl_url) as response:
            crl_data = response.read()
        
        print(f"CRL baixada com sucesso ({len(crl_data)} bytes)\n")
        
        # Parse CRL usando cryptography
        from cryptography import x509
        from cryptography.hazmat.primitives import hashes
        
        # Tentar carregar como DER (formato comum)
        try:
            crl = x509.load_der_x509_crl(crl_data)
        except:
            # Tentar PEM se DER falhar
            crl = x509.load_pem_x509_crl(crl_data)
        
        print("=" * 70)
        print("INFORMAÇÕES DA CRL")
        print("=" * 70)
        
        # Issuer (quem assinou a CRL - é o certificado CA LCR que precisamos!)
        print(f"\nIssuer (CA que assinou esta CRL):")
        print(f"   {crl.issuer.rfc4514_string()}")
        
        # Extrair Common Name do issuer
        from cryptography.x509.oid import NameOID
        issuer_cn = crl.issuer.get_attributes_for_oid(NameOID.COMMON_NAME)
        if issuer_cn:
            print(f"\n   Common Name: {issuer_cn[0].value}")
            print(f"\n   ESTE É O CERTIFICADO QUE PRECISAMOS BAIXAR!")
        
        # Datas
        print(f"\nÚltima atualização: {crl.last_update_utc if hasattr(crl, 'last_update_utc') else crl.last_update}")
        print(f"Próxima atualização: {crl.next_update_utc if hasattr(crl, 'next_update_utc') else crl.next_update}")
        
        # Certificados revogados
        revoked_certs = list(crl)
        print(f"\nTotal de certificados revogados: {len(revoked_certs)}")
        
        if revoked_certs:
            print(f"\n   Primeiros 5 certificados revogados:")
            for i, revoked in enumerate(revoked_certs[:5], 1):
                print(f"   {i}. Serial: {revoked.serial_number} | Revogado em: {revoked.revocation_date_utc if hasattr(revoked, 'revocation_date_utc') else revoked.revocation_date}")
        
        # Extensões (podem ter URLs úteis)
        print(f"\nExtensões:")
        for ext in crl.extensions:
            print(f"   - {ext.oid._name}: {ext.critical}")
            
            # Tentar extrair AIA (Authority Information Access)
            if 'authorityInfoAccess' in ext.oid._name or 'IssuingDistributionPoint' in ext.oid._name:
                print(f"     Valor: {ext.value}")
        
        print("\n" + "=" * 70)
        print("PRÓXIMOS PASSOS:")
        print("=" * 70)
        print("\n1. Procurar o certificado do Issuer acima no:")
        print("   - https://certificados.serpro.gov.br/arserpro/pages/information/crl.jsf")
        print("   - http://repo.iti.br/ccdocs/")
        print("   - http://acraiz.icpbrasil.gov.br/")
        print("\n2. Baixar o certificado .crt/.cer correspondente")
        print("3. Adicionar ao projeto em certs/")
        print("4. Instalar no system trust store\n")
        
        return True
        
    except Exception as e:
        print(f"Erro ao processar CRL: {e}")
        import traceback
        traceback.print_exc()
        return False


if __name__ == '__main__':
    # CRL do certificado Gov.br (identificada no inspect_pdf_cert.py)
    crl_url = "http://repo.iti.br/lcr/public/acf/LCRacfGovBr.crl"
    
    print("INSPETOR DE CRL - Identificar Certificado CA LCR\n")
    
    if len(sys.argv) > 1:
        crl_url = sys.argv[1]
    
    inspect_crl(crl_url)
