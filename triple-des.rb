# frozen_string_literal: true

require 'rspec/autorun'

module TripleDes
  class Encrypt
    def initialize(src, key)
      @src = src
      @key = key
    end

    def call
      io = IO.popen(['./triple-des', "-text=#{src}", "-key=#{key}"])

      res = io.read.strip
      io.close
      res
    end

    private

    attr_reader :src, :key
  end
end

RSpec.describe TripleDes::Encrypt do
  subject(:service) do
    described_class.new(src, key).call
  end

  let(:src) { 'VASIA MOSHN1200499491232133' }
  let(:key) { '123456789012345678901234' }

  context 'when text encrypted' do
    it 'return base64 string' do
      expect(service).to eql('eb75f543d000bf93c8c634b5c638bc4b31912b30c899efd492102d95abfd4c84')
    end
  end

  context 'when decode string' do
    let(:src) { 'eb75f543d000bf93c8c634b5c638bc4b31912b30c899efd492102d95abfd4c84' }

    let(:service) { `./triple-des -text='#{src}' -key='#{key}' -d` }

    it 'return decode string' do
      expect(service).to eql("VASIA MOSHN1200499491232133\n")
    end
  end
end
