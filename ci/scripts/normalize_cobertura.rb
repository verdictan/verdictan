#!/usr/bin/env ruby
# Copyright (c) Verdictan.com
# SPDX-License-Identifier: BUSL-1.1

require "stringio"
require "digest"

class ConflictingCoberturaMethod < StandardError; end

def xml_attribute(line, name)
  value = line[/\b#{Regexp.escape(name)}="([^"]*)"/, 1]
  raise "missing #{name} attribute in #{line.strip}" unless value

  value
end

def method_line_coverage(method_xml)
  method_xml.lines.filter_map do |line|
    next unless line.include?("<line ")

    condition = line.match(/condition-coverage="\d+% \((\d+)\/(\d+)\)"/)&.captures
    [
      xml_attribute(line, "number"),
      {
        raw: line,
        hits: Integer(xml_attribute(line, "hits"), 10),
        branch: xml_attribute(line, "branch"),
        covered_conditions: condition ? Integer(condition.fetch(0), 10) : 0,
        total_conditions: condition ? Integer(condition.fetch(1), 10) : 0
      }
    ]
  end.to_h
end

def method_structure(method_xml)
  method_line_coverage(method_xml).map do |number, line|
    [number, line.fetch(:branch), line.fetch(:total_conditions)].join(":")
  end.join("|")
end

def disambiguate_method_name(method_xml, structure)
  suffix = Digest::SHA256.hexdigest(structure).slice(0, 12)
  method_xml.sub(/(<method\s+name=")([^"]*)"/) do
    "#{Regexp.last_match(1)}#{Regexp.last_match(2)}@coverage-#{suffix}\""
  end
end

def decimal_rate(covered, total)
  return "1" if total.zero?

  format("%.6f", covered.fdiv(total)).sub(/0+\z/, "").sub(/\.\z/, "")
end

def merge_method_xml(left, right, method_key)
  left_lines = method_line_coverage(left)
  right_lines = method_line_coverage(right)
  unless left_lines.keys == right_lines.keys
    raise ConflictingCoberturaMethod,
          "conflicting source lines for Cobertura method #{method_key.join("::")}"
  end

  merged = left.dup
  left_lines.each do |number, left_line|
    right_line = right_lines.fetch(number)
    unless left_line.fetch(:branch) == right_line.fetch(:branch) &&
           left_line.fetch(:total_conditions) == right_line.fetch(:total_conditions)
      raise ConflictingCoberturaMethod,
            "conflicting branch structure for Cobertura method #{method_key.join("::")} line #{number}"
    end

    hits = [left_line.fetch(:hits), right_line.fetch(:hits)].max
    covered_conditions = [
      left_line.fetch(:covered_conditions),
      right_line.fetch(:covered_conditions)
    ].max
    total_conditions = left_line.fetch(:total_conditions)
    replacement = left_line.fetch(:raw).sub(/hits="\d+"/, "hits=\"#{hits}\"")
    if total_conditions.positive?
      percent = covered_conditions * 100 / total_conditions
      replacement = replacement.sub(
        /condition-coverage="\d+% \(\d+\/\d+\)"/,
        "condition-coverage=\"#{percent}% (#{covered_conditions}/#{total_conditions})\""
      )
    end
    merged.sub!(left_line.fetch(:raw), replacement)
  end

  merged_lines = method_line_coverage(merged).values
  covered_lines = merged_lines.count { |line| line.fetch(:hits).positive? }
  total_conditions = merged_lines.sum { |line| line.fetch(:total_conditions) }
  covered_conditions = merged_lines.sum { |line| line.fetch(:covered_conditions) }
  merged.sub!(/line-rate="[^"]+"/, "line-rate=\"#{decimal_rate(covered_lines, merged_lines.length)}\"")
  merged.sub!(/branch-rate="[^"]+"/, "branch-rate=\"#{decimal_rate(covered_conditions, total_conditions)}\"")
  merged
end

def normalize_cobertura(input, output)
  class_name = nil
  methods = {}
  method_structures = Hash.new { |hash, key| hash[key] = [] }
  method_order = []
  method_lines = nil
  method_key = nil
  in_methods = false
  total_methods = 0
  duplicate_methods = 0
  disambiguated_methods = 0

  input.each_line do |line|
    if method_lines
      method_lines << line
      next unless line.include?("</method>")

      method_xml = method_lines.join
      structure = method_structure(method_xml)
      identity = method_key + [structure]
      if methods.key?(identity)
        methods[identity] = merge_method_xml(methods.fetch(identity), method_xml, method_key)
        duplicate_methods += 1
      else
        unless method_structures[method_key].empty?
          method_xml = disambiguate_method_name(method_xml, structure)
          disambiguated_methods += 1
        end
        method_structures[method_key] << structure
        methods[identity] = method_xml
        method_order << identity
      end
      method_lines = nil
      method_key = nil
      next
    end

    if line.include?("<class ")
      raise "nested Cobertura class" if class_name

      class_name = xml_attribute(line, "name")
      methods = {}
      method_structures = Hash.new { |hash, key| hash[key] = [] }
      method_order = []
    end

    in_methods = true if class_name && line.include?("<methods>")

    if line.include?("<method ")
      raise "Cobertura method outside a class" unless class_name

      method_lines = [line]
      method_key = [
        class_name,
        xml_attribute(line, "name"),
        xml_attribute(line, "signature")
      ]
      total_methods += 1
      next
    end

    if in_methods && line.include?("</methods>")
      method_order.each { |key| output.write(methods.fetch(key)) }
      in_methods = false
    end

    output.write(line)
    class_name = nil if line.include?("</class>")
  end

  raise "unterminated Cobertura method" if method_lines
  raise "unterminated Cobertura methods" if in_methods
  raise "unterminated Cobertura class #{class_name}" if class_name

  [total_methods, duplicate_methods, disambiguated_methods]
end

def self_test
  prefix = <<~XML
    <?xml version="1.0"?>
    <coverage><packages><package><classes>
    <class name="src.example.rs"><methods>
  XML
  method = <<~XML
    <method name="example::test" signature="" line-rate="1" branch-rate="1">
    <lines>
    <line number="1" hits="1" branch="false"/>
    </lines>
    </method>
  XML
  suffix = <<~XML
    </methods></class>
    </classes></package></packages></coverage>
  XML
  output = StringIO.new
  counts = normalize_cobertura(StringIO.new(prefix + method + method + suffix), output)
  raise "self-test did not remove one duplicate" unless counts == [2, 1, 0]
  raise "self-test changed the retained method" unless output.string.scan(method).length == 1

  uncovered = method.sub('line-rate="1"', 'line-rate="0"').sub('hits="1"', 'hits="0"')
  merged_output = StringIO.new
  merged_counts = normalize_cobertura(
    StringIO.new(prefix + uncovered + method + suffix),
    merged_output
  )
  raise "self-test did not merge duplicate coverage" unless merged_counts == [2, 1, 0]
  raise "self-test did not retain covered lines" unless merged_output.string.include?('hits="1"')
  raise "self-test did not recompute the line rate" unless merged_output.string.include?('line-rate="1"')

  conflicting = method.sub('number="1"', 'number="2"')
  collision_output = StringIO.new
  collision_counts = normalize_cobertura(
    StringIO.new(prefix + method + conflicting + suffix),
    collision_output
  )
  raise "self-test did not preserve a structural collision" unless collision_counts == [2, 0, 1]
  raise "self-test did not disambiguate a structural collision" unless collision_output.string.include?("@coverage-")
end

if ARGV == ["--self-test"]
  self_test
  puts "Cobertura normalizer self-test passed."
  exit 0
end

abort "usage: normalize_cobertura.rb COVERAGE_XML" unless ARGV.length == 1

path = File.expand_path(ARGV.fetch(0))
temporary_path = "#{path}.normalized"
begin
  counts = File.open(path, "r") do |input|
    File.open(temporary_path, "w") do |output|
      result = normalize_cobertura(input, output)
      output.flush
      output.fsync
      result
    end
  end
  File.rename(temporary_path, path)
rescue StandardError
  File.delete(temporary_path) if File.exist?(temporary_path)
  raise
end

puts "Normalized #{counts.fetch(0)} Cobertura methods; merged #{counts.fetch(1)} duplicate profiles and disambiguated #{counts.fetch(2)} structural collisions."
