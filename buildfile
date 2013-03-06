
THIS_VERSION = ENV['version'] || 'SNAPSHOT'

require 'buildr/ivy_extension'
repositories.remote << 'http://www.ibiblio.org/maven2'
repositories.release_to = 'sftp://joist.ws/var/www/joist.repo'
repositories.release_to[:permissions] = 0644

# to resolve the ${version} in the ivy.xml
Java.java.lang.System.setProperty("version", THIS_VERSION)

i = Buildr.settings.build['ivy'] = {}
i['home.dir'] = "#{ENV['HOME']}/.ivy2"
i['settings.file'] = './ivysettings.xml'

define 'secure-cookies' do
  project.group = 'com.bizo'
  project.version = THIS_VERSION
  package_with_sources

  ivy.compile_conf(['compile', 'provided']).test_conf('test')
  compile.using :source => '1.6', :target => '1.6'

  package(:jar).pom.tap do |pom|
    pom.enhance [task('ivy:makepom')]
    pom.from 'target/pom.xml'
  end
end

