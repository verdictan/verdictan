#!/usr/bin/env ruby
# frozen_string_literal: true

def normalize_formula(source)
  formula = source.gsub(/^  version "[^"]+"\n/, "")
  formula = formula.sub(/^  desc "Verdictan (.+)"$/, '  desc "\1"')

  aliases_pattern = /^  BINARY_ALIASES = \{\n(?<entries>(?:    "[^"]+":[[:space:]]+\{\},?\n)+)  \}(?:\.freeze)?\n/
  aliases_match = formula.match(aliases_pattern)
  abort "normalize_homebrew_formula.rb: BINARY_ALIASES has an unexpected format" unless aliases_match

  aliases = aliases_match[:entries].scan(/^    "([^"]+)":/).flatten
  widest_alias = aliases.map(&:length).max
  normalized_aliases = aliases.map do |name|
    %(    "#{name}":#{" " * (widest_alias - name.length + 1)}{},\n)
  end.join
  formula.sub!(aliases_pattern, "  BINARY_ALIASES = {\n#{normalized_aliases}  }.freeze\n")

  unless formula.include?("\n  test do\n")
    final_end = formula.rindex("\nend\n")
    abort "normalize_homebrew_formula.rb: formula has no final class end" unless final_end

    test_block = "\n\n  test do\n" \
                 "    assert_match version.to_s, shell_output(\"\#{bin}/verdictan --version\")\n" \
                 "  end"
    formula.insert(final_end, test_block)
  end

  description = formula[/^  desc "([^"]+)"$/, 1]
  abort "normalize_homebrew_formula.rb: formula description is missing" unless description
  abort "normalize_homebrew_formula.rb: description starts with the formula name" if description.start_with?("Verdictan ")

  formula
end

if ARGV == ["--self-test"]
  sample = <<~'FORMULA'
    class Verdictan < Formula
      desc "Verdictan AI governance gateway"
      version "1.2.3"

      BINARY_ALIASES = {
        "aarch64-apple-darwin": {},
        "x86_64-unknown-linux-gnu": {}
      }
    end
  FORMULA
  normalized = normalize_formula(sample)
  abort "self-test: explicit version remains" if normalized.include?('version "1.2.3"')
  abort "self-test: description was not normalized" unless normalized.include?('desc "AI governance gateway"')
  abort "self-test: aliases are not frozen" unless normalized.include?("  }.freeze\n")
  abort "self-test: formula test is missing" unless normalized.include?("  test do\n")
  abort "self-test: normalization is not idempotent" unless normalize_formula(normalized) == normalized
  puts "normalize_homebrew_formula.rb: self-test passed"
  exit 0
end

path = ARGV.fetch(0) do
  abort "usage: normalize_homebrew_formula.rb <formula-path>"
end
abort "normalize_homebrew_formula.rb: unexpected argument" unless ARGV.length == 1

source = File.read(path)
normalized = normalize_formula(source)
File.write(path, normalized) unless normalized == source
