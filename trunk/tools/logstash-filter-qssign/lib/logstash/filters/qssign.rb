# encoding: utf-8
require "logstash/filters/base"
require "logstash/namespace"

#
# This "qssign" filter validates the signature and sequence number
# of log messages and sets the "signature" field accordingly.
#
# You may use http://mod-qos.sourceforge.net/qssign.1.html
# to sign your log data before storing/transferring it.
#
# See http://mod-qos.sourceforge.net/ for further
# details.
#
# Copyright (C) 2019 Pascal Buchbinder
#
# Licensed to the Apache Software Foundation (ASF) under one or more
# contributor license agreements.  See the NOTICE file distributed with
# this work for additional information regarding copyright ownership.
# The ASF licenses this file to You under the Apache License, Version 2.0
# (the "License"); you may not use this file except in compliance with
# the License.  You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

class LogStash::Filters::Qssign < LogStash::Filters::Base

  config_name "qssign"
  
  # Sample configuration:
  #
  # filter {
  #   grok {
  #     match => [ "message", "%{GREEDYDATA:data} %{INT:sequence}#%{NOTSPACE:hmac}" ]
  #     tag_on_failure => [ ]
  #   }
  #   if [data] {
  #     qssign {
  #       message => "data"
  #       source => "path"
  #       sequence => "sequence"
  #       hmac => "hmac"
  #       secret => "password"
  #     }
  #     mutate {
  #       replace => [ "message", "%{data}" ]
  #       remove_field => [ "data" ]
  #     }
  #   } else {
  #     mutate {
  #       add_field => [ "signature", "missing" ]
  #     }
  #   }
  # }

  config :message, :validate => :string, :default => "data"
  config :source, :validate => :string, :default => "path"
  config :sequence, :validate => :string, :default => "sequence"
  config :hmac, :validate => :string, :default => "hmac"
  config :secret, :validate => :string, :default => "12345"

  def initialize(params)
    super(params)
    @sources = Hash.new
    @key = @secret
    # optionally: read the shared secret from a file
    if File.file?(@secret)
      value = `#{@secret}`
      @key = value.strip
    end
  end
  
  public
  def register

  end # def register

  public
  def filter(event)
    validHMAC = 0

    # read the event fields...
    # path of the file:
    source = event[@source]
    # sequence:
    sequence = event[@sequence]
    # hmac:
    hmac = event[@hmac]
    # data:
    data = event[@message]

    # raw message:
    raw = data + " " + sequence

    # calculate hmac
    digest = OpenSSL::Digest.new('sha1')
    hmacin = OpenSSL::HMAC.digest(digest, @key, raw)
    encodedHmacin = Base64.strict_encode64(hmacin)

    if (encodedHmacin <=> hmac) == 0
      if encodedHmacin.length > 0
        validHMAC = 1
      end
    end
    if validHMAC == 1
      sequenceNr = sequence.to_i
      expected = @sources[source]
      if expected == nil
        # first message from this source
        event["signature"] = "valid"
      else
        if expected == sequenceNr
          event["signature"] = "valid"
        else
          event["signature"] = "wrong sequence"
        end
      end
      nextSequence = sequenceNr + 1
      @sources[source] = nextSequence
      if data.end_with?(" qssign---end-of-data")
        @sources[source] = 1
        event["type"] = "qssign"
      end
    else
      event["signature"] = "invalid"
    end

    filter_matched(event)
  end # def filter
end # class LogStash::Filters::Qssign
