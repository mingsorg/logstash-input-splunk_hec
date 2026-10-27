# Runs only inside an isolated official Logstash test container.
require 'fileutils'
gem = Dir['/work/logstash-input-splunk_hec-*-java.gem'].sort.last
abort 'build the plugin gem first' unless gem
unless File.exist?('/run-hec/.installed')
  abort 'plugin install failed' unless system('/usr/share/logstash/bin/logstash-plugin', 'install', '--local', '--no-verify', gem)
  File.write('/run-hec/.installed', 'same-container restart marker')
end
exec '/usr/share/logstash/bin/logstash', '--path.settings', '/run-hec/config'
