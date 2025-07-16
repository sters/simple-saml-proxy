#!/usr/bin/env python3
import sys
import base64
import urllib.parse
import zlib
from lxml import etree

def decode_saml_request(url):
    """Decode and print SAML request from URL"""
    try:
        # Extract SAMLRequest parameter
        parsed = urllib.parse.urlparse(url)
        params = urllib.parse.parse_qs(parsed.query)
        
        if 'SAMLRequest' not in params:
            print("No SAMLRequest parameter found in URL")
            return
        
        saml_request = params['SAMLRequest'][0]
        print(f"Encoded SAMLRequest: {saml_request[:50]}...")
        
        # Base64 decode
        decoded = base64.b64decode(saml_request)
        
        # Try to decompress (SAML requests are often deflated)
        try:
            decompressed = zlib.decompress(decoded, -15)  # -15 for raw deflate
            xml_data = decompressed
            print("✓ Successfully decompressed SAML request")
        except:
            xml_data = decoded
            print("✓ SAML request was not compressed")
        
        # Parse XML
        root = etree.fromstring(xml_data)
        
        # Pretty print
        print("\n=== SAML Request XML ===")
        print(etree.tostring(root, pretty_print=True, encoding='unicode'))
        
        # Extract key fields
        print("\n=== Key Fields ===")
        
        # Get namespaces
        nsmap = root.nsmap
        saml_ns = nsmap.get('saml', 'urn:oasis:names:tc:SAML:2.0:assertion')
        samlp_ns = nsmap.get('samlp', 'urn:oasis:names:tc:SAML:2.0:protocol')
        
        # ID
        print(f"ID: {root.get('ID')}")
        
        # Destination
        print(f"Destination: {root.get('Destination')}")
        
        # Issuer
        issuer_elem = root.find(f'.//{{{saml_ns}}}Issuer')
        if issuer_elem is not None:
            print(f"Issuer: {issuer_elem.text}")
        
        # ACS URL
        print(f"AssertionConsumerServiceURL: {root.get('AssertionConsumerServiceURL')}")
        
        # Protocol Binding
        print(f"ProtocolBinding: {root.get('ProtocolBinding')}")
        
    except Exception as e:
        print(f"Error decoding SAML request: {e}")
        import traceback
        traceback.print_exc()

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python decode-saml.py '<URL>'")
        print("Example: python decode-saml.py 'http://localhost:8080/realms/test/protocol/saml?SAMLRequest=...'")
        sys.exit(1)
    
    decode_saml_request(sys.argv[1])