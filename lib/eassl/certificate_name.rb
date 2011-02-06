require 'openssl'
require 'eassl'
module EaSSL
  # Author::    Paul Nicholson  (mailto:paul@webpowerdesign.net)
  # Co-Author:: Adam Williams (mailto:adam@thewilliams.ws)
  # Copyright:: Copyright (c) 2006 WebPower Design
  # License::   Distributes under the same terms as Ruby
  class CertificateName
    def initialize(options)
      @options = {
        :country      => "US",
        :state        => "North Carolina",
        :city         => "Fuquay Varina",
        :organization => "WebPower Design",
        :department   => "Web Security",
        :common_name  =>  nil,                     # required
        :email        => "eassl@rubyforge.org",
      }.update(options.symbolize_keys)
    end
    
    def ssl
      OpenSSL::X509::Name.new([
        ['C',             @options[:country],      OpenSSL::ASN1::PRINTABLESTRING],
        ['ST',            @options[:state],        OpenSSL::ASN1::PRINTABLESTRING],
        ['L',             @options[:city],         OpenSSL::ASN1::PRINTABLESTRING],
        ['O',             @options[:organization], OpenSSL::ASN1::UTF8STRING],
        ['OU',            @options[:department],   OpenSSL::ASN1::UTF8STRING],
        ['CN',            @options[:common_name],  OpenSSL::ASN1::UTF8STRING],
        ['emailAddress',  @options[:email],        OpenSSL::ASN1::UTF8STRING]
      ])
    end

    def options
      @options
    end
  end
end
