#!/bin/sh

version=`grep "s.version" logstash-filter-qssign.gemspec | awk -F"'" '{print $2}'`
destination=`ls -d /opt/elasticsearch/logstash-*`
jruby=`ls -d $destination/vendor/bundle/jruby/*`
mkdir -p ${jruby}/gems/logstash-filter-qssign-$version/lib/logstash/filters/

cp lib/logstash/filters/qssign.rb ${jruby}/gems/logstash-filter-qssign-$version/lib/logstash/filters/
cp logstash-filter-qssign.gemspec ${jruby}/gems/logstash-filter-qssign-$version
cp logstash-filter-qssign.gemspec ${jruby}/specifications/
echo 'gem "logstash-filter-qssign"' >> $destination/Gemfile

