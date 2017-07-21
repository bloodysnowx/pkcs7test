require 'openssl'

cert_data = File.read('./test.p12')
p12 = OpenSSL::PKCS12.new(cert_data, 'test')
signature = OpenSSL::PKCS7::sign(p12.certificate, p12.key, 'data', nil, OpenSSL::PKCS7::BINARY | OpenSSL::PKCS7::DETACHED)

File.open('./signature', 'wb+') do |file| file.write(signature.to_der) end