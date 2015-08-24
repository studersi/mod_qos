require 'spec_helper'
require "logstash/filters/qssign"

describe LogStash::Filters::Qssign do
  describe "Set to Hello World" do
    let(:config) do <<-CONFIG
      filter {
        qssign {
          message => "Hello World"
        }
      }
    CONFIG
    end

    sample("message" => "some text") do
      expect(subject).to include("message")
      expect(subject['message']).to eq('Hello World')
    end
  end
end
