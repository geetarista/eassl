require 'openssl'
require 'eassl'
module EaSSL
  # == EaSSL::Key creates and manages openSSL keys
  #
  # Author::    Paul Nicholson  (mailto:paul@webpowerdesign.net)
  # Co-Author:: Adam Williams (mailto:adam@thewilliams.ws)
  # Copyright:: Copyright (c) 2006 WebPower Design
  # License::   Distributes under the same terms as Ruby
  #
  # ==== Usage
  #
  # ===== Availible Methods - including methods provided by openSSL::PKey:
  # * public_key
  # * private_key
  # * to_text
  class Key
    # Create new Key using the provided options or using the defaults
    def initialize(options = {}) #:params: options
      @options = {
        :bits => 2048,
        :password => 'ssl_password',
      }.update(options)
    end
    
    def ssl
      unless @ssl
        # <Should use some kind of logger on this>
        # $stderr.puts "Generating #{@options[:bits]} bit key\n"
        @ssl = OpenSSL::PKey::RSA::new(@options[:bits])
      end
      @ssl
    end
    
    # This method is used to intercept and pass-thru calls to openSSL methods and instance
    # variables.
    def method_missing(method) # :nodoc: 
      ssl.send(method)
    end
    
    def private_key
      ssl
    end
    
    # Export the encrypted key, returns a string
    def to_pem
      ssl.export(OpenSSL::Cipher::DES.new('EDE3-CBC'), @options[:password])
    end
    
    # Decrypt and load a PEM encoded Key from the file system with the provided password.
    def self.load(pem_file_path, password=nil)
      new.load(File.read(pem_file_path), password)
    end
    
    # Decrypt and load a PEM encoded Key from provided string with the provided password.
    def load(pem_string, password=nil)
      begin
        @ssl = OpenSSL::PKey::RSA::new(pem_string, password || @options[:password])
      rescue
        raise "KeyLoader: Error decrypting key with password"
      end
      self
    end
  end
end