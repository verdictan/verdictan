#!/usr/bin/env ruby
# Copyright (c) Verdictan.com
# SPDX-License-Identifier: BUSL-1.1

require "yaml"

matrix_path, inventory_path = ARGV
abort "usage: verify_cli_e2e_matrix.rb MATRIX NEXTEST_INVENTORY" unless inventory_path

cases = YAML.safe_load_file(matrix_path)
abort "command matrix must be an array" unless cases.is_a?(Array)

inventory = File.readlines(inventory_path, chomp: true).filter_map do |line|
  line[/^verdictan (.+)$/, 1]
end.to_h { |test_id| [test_id, true] }

test_owners = {}
cases.each do |entry|
  path = entry.fetch("path")
  test_id = entry.fetch("behavior_test")
  abort "#{path}: behavior_test is empty" if test_id.strip.empty?
  if test_owners.key?(test_id)
    abort "#{path}: behavior_test duplicates #{test_owners.fetch(test_id)}: #{test_id}"
  end
  abort "#{path}: behavior_test is not executable: #{test_id}" unless inventory.key?(test_id)

  test_owners[test_id] = path
end

puts "Verified #{cases.length} command paths against #{test_owners.length} executable test IDs."
