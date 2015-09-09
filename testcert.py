from OpenSSL import crypto
cert = crypto.load_certificate(crypto.FILETYPE_PEM, file('cert.pem').read()) 
print cert.get_pubkey()
