#!/usr/bin/env python3
import sys
import base64
import urllib.parse
import zlib

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
            xml_data = decompressed.decode('utf-8')
            print("✓ Successfully decompressed SAML request")
        except:
            xml_data = decoded.decode('utf-8')
            print("✓ SAML request was not compressed")
        
        # Print raw XML
        print("\n=== SAML Request XML ===")
        print(xml_data)
        
        # Simple regex extraction of key fields
        import re
        
        print("\n=== Key Fields ===")
        
        # ID
        id_match = re.search(r'ID="([^"]+)"', xml_data)
        if id_match:
            print(f"ID: {id_match.group(1)}")
        
        # Destination
        dest_match = re.search(r'Destination="([^"]+)"', xml_data)
        if dest_match:
            print(f"Destination: {dest_match.group(1)}")
        
        # Issuer
        issuer_match = re.search(r'<saml:Issuer[^>]*>([^<]+)</saml:Issuer>', xml_data)
        if issuer_match:
            print(f"Issuer: {issuer_match.group(1)}")
        
        # ACS URL
        acs_match = re.search(r'AssertionConsumerServiceURL="([^"]+)"', xml_data)
        if acs_match:
            print(f"AssertionConsumerServiceURL: {acs_match.group(1)}")
        
    except Exception as e:
        print(f"Error decoding SAML request: {e}")
        import traceback
        traceback.print_exc()

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python decode-saml-simple.py '<URL>'")
        sys.exit(1)
    
    decode_saml_request(sys.argv[1])