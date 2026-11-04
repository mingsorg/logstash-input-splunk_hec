# Explicit-artifact startup for new qualification containers only. The legacy
# install_and_run.rb remains unchanged because the existing 0.1.0 lab mounts it.
version = File.read('/work/VERSION').strip
gem = "/work/logstash-input-splunk_hec-#{version}-java.gem"
abort 'build the explicitly selected plugin gem first' unless File.file?(gem)
require 'digest'
identity = Digest::SHA256.file(gem).hexdigest
if File.exist?('/run-hec/.installed') && File.read('/run-hec/.installed') != identity
  abort 'installed artifact differs from selected gem; start a fresh qualification container'
end
unless File.exist?('/run-hec/.installed')
  abort 'plugin install failed' unless system('/usr/share/logstash/bin/logstash-plugin', 'install', '--local', '--no-verify', gem)
  File.write('/run-hec/.installed', identity)
end
exec '/usr/share/logstash/bin/logstash', '--path.settings', '/run-hec/config'
