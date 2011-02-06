require 'openssl'
require 'eassl'
module EaSSL
  # Author::    Paul Nicholson  (mailto:paul@webpowerdesign.net)
  # Co-Author:: Adam Williams (mailto:adam@thewilliams.ws)
  # Copyright:: Copyright (c) 2006 WebPower Design
  # License::   Distributes under the same terms as Ruby
  class SigningRequest
    def initialize(options = {})
      @options = {
        :name       => {},                #required, CertificateName
        :key        => nil,               #required
      }.update(options)
      @options[:key] ||= Key.new(@options)
    end
  
    def ssl
      unless @ssl
        @ssl = OpenSSL::X509::Request.new
        @ssl.version = 0
        @ssl.subject = CertificateName.new(@options[:name].options).ssl
        @ssl.public_key = key.public_key
        @ssl.sign(key.private_key, OpenSSL::Digest::SHA1.new)
      end
      @ssl
    end
  
    def key
      @options[:key]
    end
  
    # This method is used to intercept and pass-thru calls to openSSL methods and instance
    # variables.
    def method_missing(method)
      ssl.send(method)
    end
  
    def self.load(pem_file_path)
      new.load(File.read(pem_file_path))
    end
  
    def load(pem_string)
      begin
        @ssl = OpenSSL::X509::Request.new(pem_string)
      rescue
        raise "SigningRequestLoader: Error loading signing request"
      end
      self
    end
  end
end
