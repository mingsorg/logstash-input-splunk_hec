# Reference startup for an already-built gem; this does not build a gem or image.
# Check the container's installation, not the old bind-mounted .installed marker:
# that marker cannot prove a newly recreated container contains the plugin.
gem = Dir['/work/logstash-input-splunk_hec-*-java.gem'].sort.last
abort 'provide the existing built plugin gem under /work' unless gem
plugins = IO.popen(['/usr/share/logstash/bin/logstash-plugin', 'list', '--verbose', 'splunk'], &:read)
abort 'could not inspect installed plugins' unless $?.success?
unless plugins.include?('logstash-input-splunk_hec (0.1.0)')
  abort 'plugin install failed' unless system('/usr/share/logstash/bin/logstash-plugin', 'install', '--local', '--no-verify', gem)
end
exec '/usr/share/logstash/bin/logstash', '--path.settings', '/run-hec/config'
