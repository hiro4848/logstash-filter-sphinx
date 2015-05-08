Gem::Specification.new do |s|
  s.name = 'logstash-filter-sphinx'
  s.version         = '0.0.2'
  s.licenses = ['Apache License (2.0)']
  s.summary = "Sphinx filter for updating event logs"
  s.description = "This gem is a logstash plugin required to be installed on top of the Logstash core pipeline using $LS_HOME/bin/plugin install gemname. This gem is not a stand-alone program"
  s.authors = ["Takehiro Takahashi"]
  s.email = 'takehiro.takahashi@gmail.com'
  s.homepage = "http://www.sphinxlog.com/"
  s.require_paths = ["lib"]

  # Files
  s.files = `git ls-files`.split($\)
   # Tests
  s.test_files = s.files.grep(%r{^(test|spec|features)/})

  # Special flag to let us know this is actually a logstash plugin
  s.metadata = { "logstash_plugin" => "true", "logstash_group" => "filter" }

  # Gem dependencies
  s.add_runtime_dependency "logstash-core", '>= 1.4.0', '< 2.0.0'
  s.add_runtime_dependency 'pg_jruby', '~> 0.14.1.rc2'
  s.add_runtime_dependency 'redis', '3.2.1'
  s.add_runtime_dependency 'ipaddress', '0.8.0'
  s.add_runtime_dependency 'connection_pool', '2.2.0'


  s.add_development_dependency 'logstash-devutils'
end
