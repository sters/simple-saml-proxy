#!/usr/bin/env python3
import sys
import base64
import urllib.parse
import zlib
import argparse
import re

def decode_saml_request(url, use_simple_parser=False):
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
            xml_data = decompressed.decode('utf-8') if use_simple_parser else decompressed
            print("✓ Successfully decompressed SAML request")
        except:
            xml_data = decoded.decode('utf-8') if use_simple_parser else decoded
            print("✓ SAML request was not compressed")
        
        # Print XML
        print("\n=== SAML Request XML ===")
        if use_simple_parser:
            print(xml_data)
            _extract_fields_simple(xml_data)
        else:
            _extract_fields_xml(xml_data)
        
    except Exception as e:
        print(f"Error decoding SAML request: {e}")
        import traceback
        traceback.print_exc()

def _extract_fields_xml(xml_data):
    """Extract fields using XML parser (requires lxml)"""
    try:
        from lxml import etree
        
        # Parse XML
        root = etree.fromstring(xml_data)
        
        # Pretty print
        print(etree.tostring(root, pretty_print=True, encoding='unicode'))
        
        # Extract key fields
        print("\n=== Key Fields ===")
        
        # Get namespaces
        nsmap = root.nsmap
        saml_ns = nsmap.get('saml', 'urn:oasis:names:tc:SAML:2.0:assertion')
        
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
        
    except ImportError:
        print("lxml not available, falling back to simple parsing")
        _extract_fields_simple(xml_data.decode('utf-8') if isinstance(xml_data, bytes) else xml_data)

def _extract_fields_simple(xml_data):
    """Extract fields using simple regex parsing"""
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
    
    # Protocol Binding
    binding_match = re.search(r'ProtocolBinding="([^"]+)"', xml_data)
    if binding_match:
        print(f"ProtocolBinding: {binding_match.group(1)}")

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description='Decode SAML requests from URLs')
    parser.add_argument('url', help='URL containing SAMLRequest parameter')
    parser.add_argument('--simple', action='store_true', 
                       help='Use simple regex parsing instead of XML parser')
    
    args = parser.parse_args()
    
    if not args.url:
        print("Usage: python decode-saml.py '<URL>' [--simple]")
        print("Example: python decode-saml.py 'http://localhost:11001/realms/test/protocol/saml?SAMLRequest=...'")
        sys.exit(1)
    
    decode_saml_request(args.url, args.simple)