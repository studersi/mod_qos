Gem::Specification.new do |s|
  s.name = 'logstash-filter-qssign'
  s.version         = '1.0.0'
  s.licenses = ['GNU GENERAL PUBLIC LICENSE (2)']
  s.summary = "This qssign filter may be used for validate log message signatures created by qssign."
  s.description = "This gem is a logstash plugin required to be installed on top of the Logstash core pipeline using $LS_HOME/bin/plugin install gemname. This gem is not a stand-alone program."
  s.authors = ["Pascal Buchbinder"]
  s.email = 'pbuchbinder@users.sourceforge.net'
  s.homepage = "http://mod-qos.sourceforge.net/"
  s.require_paths = ["lib"]

  # Files
  s.files = `./ls.sh`.split($\)
   # Tests
  s.test_files = s.files.grep(%r{^(test|spec|features)/})

  # Special flag to let us know this is actually a logstash plugin
  s.metadata = { "logstash_plugin" => "true", "logstash_group" => "filter" }

  # Gem dependencies
  s.add_runtime_dependency "logstash-core", '>= 1.4.0', '< 2.0.0'
  s.add_development_dependency 'logstash-devutils'
end
