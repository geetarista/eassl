require 'openssl'
require 'eassl'
module EaSSL
  # Author::    Paul Nicholson  (mailto:paul@webpowerdesign.net)
  # Co-Author:: Adam Williams (mailto:adam@thewilliams.ws)
  # Copyright:: Copyright (c) 2006 WebPower Design
  # License::   Distributes under the same terms as Ruby
  class Certificate
    def initialize(options)
      @options = {
        :days_valid       => (365 * 5),
        :signing_request  => nil,               #required
        :ca_certificate   => nil,               #required
        :comment          => "Ruby/OpenSSL/EaSSL Generated Certificate",
      }.update(options)
    end
    
    def ssl
      unless @ssl
        @ssl = OpenSSL::X509::Certificate.new
        @ssl.not_before = Time.now
        @ssl.subject = @options[:signing_request].subject
        @ssl.issuer = @options[:ca_certificate]? @options[:ca_certificate].subject :  @ssl.subject
        @ssl.not_after = @ssl.not_before + @options[:days_valid] * 24 * 60 * 60
        @ssl.public_key = @options[:signing_request].public_key
        @ssl.serial = @options[:serial] || 2
        @ssl.version = 2 # X509v3
      
        ef = OpenSSL::X509::ExtensionFactory.new
        ef.subject_certificate = @ssl
        ef.issuer_certificate = @options[:ca_certificate]? @options[:ca_certificate].ssl : @ssl
        @ssl.extensions = [
          ef.create_extension("basicConstraints","CA:FALSE"),
          ef.create_extension("keyUsage", "digitalSignature, keyEncipherment"),
          ef.create_extension("subjectKeyIdentifier", "hash"),
          ef.create_extension("extendedKeyUsage", "serverAuth"),
          ef.create_extension("nsComment", @options[:comment]),
        ]
        @ssl.add_extension(ef.create_extension("authorityKeyIdentifier", "keyid:always,issuer:always"))
      end
      @ssl
    end

    def sign(ca_key)
      ssl.sign(ca_key.ssl, OpenSSL::Digest::SHA1.new)
    end

    def to_pem
      ssl.to_pem
    end
    
    def self.load(pem_file_path)
      new({}).load(File.read(pem_file_path))
    end

    def load(pem_string)
      begin
        @ssl = OpenSSL::X509::Certificate.new(pem_string)
      rescue
        raise "CertificateLoader: Error loading certificate"
      end
      self
    end
  end
end