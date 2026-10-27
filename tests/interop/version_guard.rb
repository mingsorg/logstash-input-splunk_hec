# Prove that the Ruby runtime floor is checked independently of the reusable Java API.
require 'java'
require 'json'
module LogStash
  module Inputs
    class Base; end
  end
end
$LOADED_FEATURES.concat(['logstash/inputs/base.rb','logstash/namespace.rb','logstash/version.rb'])
Object.const_set(:LOGSTASH_VERSION,'9.4.99')
begin
  load '/work/lib/logstash/inputs/splunk_hec.rb'
  abort 'pre-9.5 floor was not enforced'
rescue LoadError => error
  raise unless error.message.include?('requires Logstash 9.5.0')
  puts JSON.generate({api_distribution:ARGV[0],reported_runtime:'9.4.99',rejected:true})
end
