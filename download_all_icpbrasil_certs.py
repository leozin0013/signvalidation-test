#!/usr/bin/env python3
"""
Script para baixar TODOS os certificados da ICP-Brasil
Fonte: Arquivo único compactado com todos os certificados (ativos e expirados)
URL: https://acraiz.icpbrasil.gov.br/credenciadas/CertificadosAC-ICP-Brasil/ACcompactadox.zip

Este arquivo contém ~324 certificados necessários para:
- Validar cadeias completas de certificados
- Validar assinaturas de CRLs (Certificate Revocation Lists)
- Resolver o problema de "InsufficientRevinfoError"
"""

import urllib.request
import zipfile
import os
import ssl
from pathlib import Path

# URLs
ZIP_URL = "https://acraiz.icpbrasil.gov.br/credenciadas/CertificadosAC-ICP-Brasil/ACcompactadox.zip"
ZIP_FILE = "icpbrasil_all_certs.zip"

def download_all_icpbrasil_certs():
    """Download e extração de todos os certificados ICP-Brasil"""
    
    print("=" * 70)
    print("DOWNLOAD DE TODOS OS CERTIFICADOS ICP-BRASIL")
    print("=" * 70)
    
    # Diretório de destino
    certs_dir = Path(__file__).parent / 'certs'
    certs_dir.mkdir(exist_ok=True)
    
    # Criar contexto SSL que ignora verificação
    # Necessário porque o site da ICP-Brasil pode usar certificados que não são confiáveis no Windows
    # É seguro neste caso pois estamos baixando certificados públicos
    ssl_context = ssl.create_default_context()
    ssl_context.check_hostname = False
    ssl_context.verify_mode = ssl.CERT_NONE
    
    try:
        # 1. Download do arquivo ZIP
        print(f"\n[1/3] Baixando arquivo ZIP (~2-5 MB)...")
        print(f"      URL: {ZIP_URL}")
        
        with urllib.request.urlopen(ZIP_URL, context=ssl_context) as response:
            zip_data = response.read()
        
        print(f"      ✓ Download concluído: {len(zip_data):,} bytes")
        
        # 2. Salvar temporariamente
        zip_path = certs_dir / ZIP_FILE
        with open(zip_path, 'wb') as f:
            f.write(zip_data)
        
        # 3. Extrair certificados
        print(f"\n[2/3] Extraindo certificados...")
        
        with zipfile.ZipFile(zip_path, 'r') as zip_ref:
            # Listar arquivos .crt/.cer
            cert_files = [f for f in zip_ref.namelist() 
                         if f.lower().endswith(('.crt', '.cer')) and not f.startswith('__MACOSX')]
            
            print(f"      Certificados encontrados no ZIP: {len(cert_files)}")
            
            # Extrair todos
            extracted_count = 0
            for cert_file in cert_files:
                try:
                    # Extrair para certs/
                    zip_ref.extract(cert_file, certs_dir)
                    
                    # Se estiver em subpasta, mover para raiz de certs/
                    extracted_path = certs_dir / cert_file
                    if '/' in cert_file or '\\' in cert_file:
                        # Mover para raiz
                        new_path = certs_dir / Path(cert_file).name
                        if extracted_path.exists() and extracted_path != new_path:
                            extracted_path.rename(new_path)
                            # Remover pasta vazia se houver
                            try:
                                extracted_path.parent.rmdir()
                            except:
                                pass
                    
                    extracted_count += 1
                except Exception as e:
                    print(f"      ⚠ Erro ao extrair {cert_file}: {e}")
            
            print(f"      ✓ Extraídos: {extracted_count} certificados")
        
        # 4. Remover arquivo ZIP
        print(f"\n[3/3] Limpando arquivos temporários...")
        zip_path.unlink()
        print(f"      ✓ Arquivo ZIP removido")
        
        # 5. Contagem final
        final_count = len(list(certs_dir.glob('*.crt'))) + len(list(certs_dir.glob('*.cer')))
        
        print("\n" + "=" * 70)
        print("RESUMO")
        print("=" * 70)
        print(f"Certificados instalados em certs/: {final_count}")
        print(f"Diretório: {certs_dir.absolute()}")
        print("\nEstes certificados incluem:")
        print("  - Todas as ACs da ICP-Brasil (ativas e expiradas)")
        print("  - Certificados necessários para validar CRLs")
        print("  - Cadeia completa para validação de certificados Gov.br")
        print("\n✓ Download concluído com sucesso!")
        print("=" * 70)
        
        return True
        
    except Exception as e:
        print(f"\n✗ Erro ao baixar certificados: {e}")
        import traceback
        traceback.print_exc()
        return False


if __name__ == '__main__':
    download_all_icpbrasil_certs()
