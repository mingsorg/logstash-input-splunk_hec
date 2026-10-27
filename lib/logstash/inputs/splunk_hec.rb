require 'logstash/inputs/base'
require 'logstash/namespace'
require 'logstash/version'
require 'java'

unless Gem::Version.new(LOGSTASH_VERSION) >= Gem::Version.new('9.5.0')
  raise LoadError, 'splunk_hec requires Logstash 9.5.0 or newer (independent of plugin API version)'
end
Dir[File.expand_path('../../../vendor/jars/*.jar', __dir__)].sort.each { |jar| require jar }

class LogStash::Inputs::SplunkHec < LogStash::Inputs::Base
  config_name 'splunk_hec'
  def self.javaClass
    Java::OrgLogstashpluginsHec::SplunkHec.java_class
  end
end
