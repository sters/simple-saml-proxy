#!/bin/bash

#export PROXY_ENTITY_ID= # use default
#export PROXY_ACS_URL= # use default
#export PROXY_METADATA_URL= # use default
export PROXY_PRIVATE_KEY_PATH=$(pwd)/proxy.key
export PROXY_CERTIFICATE_PATH=$(pwd)/proxy.crt
export IDP_0_ID=SAMLKit1
export IDP_0_ENTITY_ID=https://samlkit.com/saml2/idp/adhoc
export IDP_0_SSO_URL=https://samlkit.com/saml2/receive
export IDP_0_CERTIFICATE_PATH=$(pwd)/samlkit1.crt
export SERVER_LISTEN_ADDRESS=localhost:8080

cd ..
make run
