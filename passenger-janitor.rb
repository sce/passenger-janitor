#!/usr/bin/env ruby
#
# Copyright (c) 2011, S. Christoffer Eliesen <christoffer@eliesen.no>
# (github.com/sce)
#
# Permission to use, copy, modify, and/or distribute this software for any
# purpose with or without fee is hereby granted, provided that the above
# copyright notice and this permission notice appear in all copies.
#
# THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
# WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
# MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
# ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
# WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
# ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
# OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
#
# ---
#
# (http://en.wikipedia.org/wiki/ISC_license)
#
# This script can be used to control a badly behaving Rails/Passenger setup.
#
# It is cron friendly: Only when processes are killed will it create any
# output.
#
# Inspired by other passenger process killing scripts on github.
#

require 'optparse'
require 'open3'

module Util
  private

  # Yield with input/output pipe to given command. Abort if stderr from command
  # is non-empty.
  def command(cmd)
    Open3.popen3(cmd) do |input, output, err|
      errors = err.readlines
      abort "%s\n%s" % [cmd, errors.join] if errors.any?

      yield input, output if block_given?
    end
  end

  def grace_time
    puts %((zzz for %s seconds...)) % @options[:grace]
    sleep @options[:grace]
  end

  def kill(process_stats, why)
    return if process_stats.empty?

    puts %(%s: %d processes.) % [why, process_stats.size]

    process_stats.each_pair do |pid, stats|
      puts %(%s: %s: Killing process with USR1 ... %s) % [why, pid, stats.inspect]
      Process.kill(:USR1, pid) unless @options[:dry_run]
    end

    grace_time
    remaining = (ps_stats.keys & process_stats.keys)
    return if remaining.empty?

    remaining.each do |pid|
      puts %(%s: %s: Still not dead, killing process with KILL ...) % [why, pid]
      Process.kill(:KILL, pid) unless @options[:dry_run]
    end

    grace_time
    remaining = (ps_stats.keys & process_stats.keys)
    return if remaining.empty?

    puts %(%s: %d processes STILL not dead (%s).) % [why, remaining.size, remaining.join(", ")]
  end
end

module Stats

  def passenger_status
    command("passenger-status") do |input, output|
      output.readlines.inject({}) do |hash, line|
        next hash unless match = line.match(/PID: (\d+)\s+Sessions: (\d+)\s+Processed: (\d+)\s*Uptime: ([\w ]+)/)

        pid, sessions, processed, uptime = *match.captures

        seconds = uptime.split.map do |time|
          case time
          when /(\d+)h/
            $1.to_i * 60 * 60
          when /(\d+)m/
            $1.to_i * 60
          when /(\d+)s/
            $1.to_i
          else
            raise %(Can't parse uptime part %s (%s)) % [time, uptime]
          end
        end.inject(0, &:+)

        hash[pid.to_i] = {
          :sessions  => sessions.to_i,
          :processed => processed.to_i,
          :uptime    => seconds
        }

        hash
      end
    end
  end

  def passenger_memory_stats
    command("passenger-memory-stats") do |input, output|
      output.readlines.inject({}) do |hash, line|
        next hash unless match = line.match(/([\d\.]+)\s+[\d\.]+ MB\s+([\d\.]+) MB\s+Rack: (.+)/)

        pid, mem, name = *match.captures

        hash[pid.to_i] = {
          :mem  => mem.to_i,
          :name => name
        }

        hash
      end
    end
  end

  # Return stats hash with passenger_status and passenger_memory_stats
  # combined.
  def stats
    # Memory stats may show more processes than status.
    status = passenger_status
    passenger_memory_stats.each_pair.inject({}) do |hash, (pid, stats)|
      hash[pid] = stats
      stats.merge! status[pid] if status[pid]

      hash
    end
  end

  def ps_stats
    command("ps -eo pid,args") do |input, output|
      output.readlines.inject({}) do |hash, line|
        next hash unless match = line.match(/(\d+)\s+Rack: (.+)$/)
        pid, name = *match.captures

        hash[pid.to_i] = { :name => name }
        hash
      end
    end
  end

end

# Methods from this module will potentially be called when running this script,
# and they'll be executed in the order they are defined.
module CleanupActions

  # Kill Rack processes that don't show up in passenger-status (though they
  # might show up in passenger-memory-stats).
  def zombies
    passenger_pids = passenger_status.keys
    zombies = ps_stats.delete_if do |pid|
      passenger_pids.include? pid
    end

    kill zombies, "Zombie"
  end

  def fat
    fatties = stats.keep_if do |pid, stats|
      stats[:mem] >= @options[:fat]
    end

    kill fatties, "Fat"
  end

  # Kill processes we think are stale (non-empty queue and processed few
  # requests over a long period).
  #
  # This is certainly not foul proof, so we may end up killing processes simply
  # due to bad timing, but the profit outweighs the risk I think.
  def stale
    stale = stats.keep_if do |pid, stats|
      # Zombies that were not successfully killed don't have :sessions etc.
      stats[:sessions].to_i  >  0  and
      stats[:processed].to_i <  10 and
      stats[:uptime].to_i    >= @options[:stale]
    end

    kill stale, "Stale"
  end

  # Processes that have lived for a "long" time might have gone stale.
  def old
    oldies = stats.keep_if do |pid, stats|
      stats[:uptime].to_i >= @options[:old]
    end

    kill oldies, "Old"
  end
end

class PassengerJanitor
  include Util
  include Stats
  include CleanupActions

  def initialize(options)
    @options = options
  end

  def run
    actions = CleanupActions.instance_methods.find_all {|name| @options.key? name}
    abort @options[:opts].to_s if actions.empty?

    actions.each do |name|
      send name
    end
  end
end

defaults = {
  :fat     => 1024,
  :old     => 3600 * 4,
  :stale   => 3600
}

options = {
  :grace   => 30,
  :dry_run => false
}

OptionParser.new do |opts|
  opts.banner = (<<-BANNER).gsub(/^ {4}/, '')
    Clean up passenger processes.

    This program will run passenger-status and passenger-memory-stats and use
    the returned information to determine which processes to kill.

    It must be run as root (or rvmsudo) to work properly. No output is given
    unless attempting to kill a process, making it suitable for use with cron.

    Use options to activate a reason and possibly change default values.

    Usage:
      #{$0} [options]

    Categories to kill (with default values in round brackets):
  BANNER

  opts.on("-f[MEGABYTES]", "--fat[=MEGABYTES]", Integer,
    "Kill processes with more than MEGABYTE (#{defaults[:fat]}) memory use.") \
    {|i| options[:fat] = i || defaults[:fat]}

  opts.on("-o[SECONDS]", "--old[=SECONDS]", Integer,
    "Kill processes with more than SECONDS (#{defaults[:old]}) uptime.") \
    {|i| options[:old] = i || defaults[:old]}

  opts.on("-s[SECONDS]", "--stale[=SECONDS]", Integer,
    "Kill seemingly stale processes with more than SECONDS (#{defaults[:stale]}) uptime.") \
    {|i| options[:stale] = i || defaults[:stale]}

  opts.on("-z", "--zombies",
    "Kill Rack processes that don't show up in passenger-status.") \
    { options[:zombies] = true }

  opts.separator ""
  opts.separator "Common options:"

  opts.on("-gSECONDS", "--grace SECONDS", Integer,
    "Give processes SECONDS (#{options[:grace]}) to die gracefully.") \
    {|i| options[:grace] = i }

  opts.on("-n", "--dry-run", "Don't actually kill processes.") { options[:dry_run] = true }
  opts.on("-h", "--help",    "Show this.")                     { puts opts; exit }

  options[:opts] = opts
end.parse!

PassengerJanitor.new(options).run
