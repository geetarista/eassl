require 'openssl'
require 'eassl'
module EaSSL
  # Author::    Paul Nicholson  (mailto:paul@webpowerdesign.net)
  # Co-Author:: Adam Williams (mailto:adam@thewilliams.ws)
  # Copyright:: Copyright (c) 2006 WebPower Design
  # License::   Distributes under the same terms as Ruby
  class CertificateAuthority
    attr_reader :key, :certificate
    def initialize(options = {})
      @key = Key.new({:password => 'ca_ssl_password'}.update(options))
      @certificate = AuthorityCertificate.new(:key => @key)
    end
    
    def create_certificate(signing_request)
      cert = Certificate.new(:signing_request => signing_request, :ca_certificate => @certificate)
      cert.sign(@key)
      cert
    end
  end
end