# encoding: utf-8
require "logstash/filters/base"
require "logstash/namespace"

#require 'digest'

# This qssign filter will replace the contents of the default 
# message field with whatever you specify in the configuration.
#
# It is only intended to be used as an qssign.
class LogStash::Filters::Qssign < LogStash::Filters::Base

  # Setting the config_name here is required. This is how you
  # configure this filter from your Logstash config.
  #
  # filter {
  #   qssign {
  #     message => "My message..."
  #   }
  # }
  #
  config_name "qssign"
  
  # Sample configuration:
  #
  # filter {
  #   grok {
  #     match => [ "message", "%{GREEDYDATA:data} %{INT:sequence}#%{NOTSPACE:hmac}" ]
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

  #sources = Hash.new
  
  public
  def register
    # list of known input sources:
    #sources = Hash.new
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
      seqenceNr = sequence.to_i
      #expected = sources[source]
      #if expected == nil
      #  # first message from this source
      #  event["signature"] = "valid"
      #else
      #  if expected == nextSequnce
      #    event["signature"] = "valid"
      #  else
      #    event["signature"] = "wrong sequence"
      #  end
      #end
      #nextSequence = sequence + 1
      #sources[source] = nextSequence
      event["signature"] = "valid"
    else
      event["signature"] = "invalid"
    end
    
    filter_matched(event)
  end # def filter
end # class LogStash::Filters::Qssign
