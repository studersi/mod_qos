# encoding: utf-8
require "logstash/filters/base"
require "logstash/namespace"

#require 'digest'

#
# This "qssign" filter validates the signature and sequence number
# of log messages and sets the "signature" field accordingly.
#
# You may use http://opensource.adnovum.ch/mod_qos/qssign.1.html
# to sign your log data before storing/transferring it.
#
# See http://opensource.adnovum.ch/mod_qos/ for further
# details.
#
# Copyright (C) 2015 Pascal Buchbinder
#
# This program is free software; you can redistribute it and/or
# modify it under the terms of the GNU General Public License
# as published by the Free Software Foundation; either version 2
# of the License, or (at your option) any later version.
#
# This program is released under the GPL with the additional
# exemption that compiling, linking, and/or using OpenSSL is allowed.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston,
# MA 02110-1301, USA.

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

    # configured shared secret:
    key = @secret

    # raw message:
    raw = data + " " + sequence

    # calculate hmac
    digest = OpenSSL::Digest.new('sha1')
    hmacin = OpenSSL::HMAC.digest(digest, key, raw)
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
      end
    else
      event["signature"] = "invalid"
    end
    
    filter_matched(event)
  end # def filter
end # class LogStash::Filters::Qssign
