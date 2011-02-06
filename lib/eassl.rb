require 'openssl'
require 'fileutils'
$:.unshift File.expand_path(File.dirname(__FILE__))
# = About EaSSL
#
# Author::    Paul Nicholson  (mailto:paul@webpowerdesign.net)
# Co-Author:: Adam Williams (mailto:adam@thewilliams.ws)
# Copyright:: Copyright (c) 2006 WebPower Design
# License::   Distributes under the same terms as Ruby
#
# By requiring <tt>eassl</tt>, you can load the full set of EaSSL classes.
#
# For a full list of features and instructions, see the #README.
#
# EaSSL is a module containing all of the great EaSSL classes for creating 
# and managing openSSL keys, signing request, and certificates.
# 
# * EaSSL::Key: the class for loading and creating SSL keys
# * EaSSL::SigningRequest: the class for creating SSL signing requests

module EaSSL
  VERSION = '0.1'
  
  def self.generate_self_signed(options)
    ca = CertificateAuthority.new({:bits => 1024}.update(options[:ca_options]||{}))
    sr = SigningRequest.new(options)
    cert = ca.create_certificate(sr)
    [ca, sr, cert]
  end
  
  def self.config_webrick(webrick_config, options = {})
    hostname = `hostname`.strip
    eassl_host_dir = "#{File.expand_path('~')}/.eassl/#{hostname}"
    ca_cert_file = "#{eassl_host_dir}/ca.crt"
    ca_key_file = "#{eassl_host_dir}/ca.key"
    server_key_file = "#{eassl_host_dir}/server.key"
    server_cert_file = "#{eassl_host_dir}/server.crt"
    FileUtils.rm_rf(eassl_host_dir) if options[:force_regeneration]
    
    if File.exist?(server_cert_file)
      key = Key.load(server_key_file, 'countinghouse1234')
      cert = Certificate.load(server_cert_file)
    else
      ca, sr, cert = self.generate_self_signed({:name => {:common_name => hostname}, :bits => 1024}.update(options))
      key = sr.key
      FileUtils.makedirs(eassl_host_dir)
      File.open(%(#{ca_cert_file}.pem), "w", 0777) {|f| f << ca.certificate.to_pem }
      File.open(%(#{ca_cert_file}.der), "w", 0777) {|f| f << ca.certificate.to_der }
      File.open(ca_key_file, "w", 0777) {|f| f << ca.key.to_pem }
      File.open(server_key_file, "w", 0777) {|f| f << key.to_pem }
      File.open(server_cert_file, "w", 0777) {|f| f << cert.to_pem }
    end
    
    webrick_config.update({
      :SSLEnable       => true,
      :SSLPrivateKey => key.ssl,
      :SSLCertificate => cert.ssl,
      :SSLExtraChainCert => [Certificate.load(%(#{ca_cert_file}.pem)).ssl],
      :SSLVerifyClient => OpenSSL::SSL::VERIFY_NONE,
      :SSLStartImmediately => true,
    })
  end
end

require 'eassl/key'
require 'eassl/certificate_name'
require 'eassl/signing_request'
require 'eassl/certificate'
require 'eassl/authority_certificate'
require 'eassl/certificate_authority'
