Gem::Specification.new do |s|
  s.name = 'logstash-filter-sqlstream'
  s.version         = '1.0.0'
  s.licenses = ['Apache License (2.0)']
  s.summary = "Support  stream-SQL based on structured text."
  s.description = "This gem is a logstash plugin required to be installed on top of the Logstash core pipeline using $LS_HOME/bin/plugin install gemname. This gem is not a stand-alone program"
  s.authors = ["hdatas"]
  s.email = ''
  s.homepage = ""
  s.require_paths = ["lib"]

  # Files
  s.files = Dir['lib/**/*','spec/**/*','vendor/**/*','*.gemspec','*.md','CONTRIBUTORS','Gemfile','LICENSE','NOTICE.TXT']
   # Tests
  s.test_files = s.files.grep(%r{^(test|spec|features)/})

  # Special flag to let us know this is actually a logstash plugin
  s.metadata = { "logstash_plugin" => "true", "logstash_group" => "filter" }

  # Gem dependencies
  s.add_runtime_dependency "logstash-core", "~> 1.5.0"

  # Grok-depend
  s.add_runtime_dependency 'jls-grok', '~> 0.11.1'
  s.add_runtime_dependency 'logstash-patterns-core'

  # sql stream
  s.add_runtime_dependency 'sequel'
  s.add_runtime_dependency 'jdbc-sqlite3'

  s.add_development_dependency 'logstash-devutils'
  # end grok-depend

end
