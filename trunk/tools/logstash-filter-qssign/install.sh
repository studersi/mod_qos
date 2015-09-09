#!/bin/sh

destination=`ls -d /opt/elasticsearch/logstash-*`
jruby=`ls -d $destination/vendor/bundle/jruby/*`
mkdir -p ${jruby}/gems/logstash-filter-qssign-1.0.0/lib/logstash/filters/

cp lib/logstash/filters/qssign.rb ${jruby}/gems/logstash-filter-qssign-1.0.0/lib/logstash/filters/
cp logstash-filter-qssign.gemspec ${jruby}/gems/logstash-filter-qssign-1.0.0
cp logstash-filter-qssign.gemspec ${jruby}/specifications/
echo 'gem "logstash-filter-qssign"' >> $destination/Gemfile
