require 'openssl'

orig_text = 'data'
cert_data = File.read('./test2.p12')
p12 = OpenSSL::PKCS12.new(cert_data, 'test')
signed_data = OpenSSL::PKCS7::sign(p12.certificate, p12.key, orig_text, p12.ca_certs, OpenSSL::PKCS7::BINARY | OpenSSL::PKCS7::DETACHED)

File.open('./ruby.signed', 'wb+') do |file| file.write(signed_data.to_der) end
pkcs7 = File.open('./ruby.signed') do |file| OpenSSL::PKCS7.new(file.read) end

store = OpenSSL::X509::Store.new
p12.ca_certs.each{|ca| store.add_cert(ca)}
verified = pkcs7.verify(nil, store, orig_text, OpenSSL::PKCS7::NOVERIFY)