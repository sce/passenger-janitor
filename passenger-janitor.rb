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
# Only tested on Linux.
#

require 'optparse'
require 'open3'

PASSENGER_STATUS       = "passenger-status"
PASSENGER_MEMORY_STATS = "passenger-memory-stats"
PS_STATS               = "ps -eo pid,args"

module Util
  private

  # Yield with input/output pipe to given command. Abort if stderr from command
  # is non-empty.
  def command(cmd)
    Open3.popen3(cmd) do |stdin, stdout, stderr|
      errors = stderr.readlines
      abort "%s\n%s" % [cmd, errors.join] if errors.any?

      yield stdin, stdout if block_given?
    end
  end

  # Yield or return with a read pipe at the end of file. Pipe is nil when
  # filename is nil.
  def tail(filename)
    if filename
      if block_given?
        File.open(filename) do |file|
          file.seek(0, IO::SEEK_END)

          yield file
        end

      else
        file = File.open(filename)
        file.seek(0, IO::SEEK_END)
        file
      end

    elsif block_given?
      yield
    end
  end

  def grace_time
    puts %((zzz for %s seconds...)\n\n) % @options[:grace]
    sleep @options[:grace]
    @logs.each { |log| log.eof? or puts(log.readlines, "") }
  end

  def kill(process_stats, why, signal=:USR1)
    return if process_stats.empty?

    puts %(%s: %d processes.) % [why, process_stats.size]

    process_stats.each_pair do |pid, stats|
      puts %(%s: %s: Killing process with %s ... %s) % [why, pid, signal, stats.inspect]
      Process.kill(signal, pid) unless @options[:dry_run]
    end

    grace_time
    return if (remaining = ps_stats.keys & process_stats.keys).empty?

    remaining.each do |pid|
      puts %(%s: %s: Still not dead, killing process with KILL ...) % [why, pid]
      Process.kill(:KILL, pid) unless @options[:dry_run]
    end

    grace_time
    return if (remaining = ps_stats.keys & process_stats.keys).empty?

    puts %(%s: %d processes STILL not dead (%s).\n\n) % [why, remaining.size, remaining.join(", ")]
  end
end

module Stats

  def passenger_status
    command(PASSENGER_STATUS) do |input, output|
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
    command(PASSENGER_MEMORY_STATS) do |input, output|
      output.readlines.inject({}) do |hash, line|
        next hash unless match = line.match(/([\d\.]+)\s+[\d\.]+ MB\s+([\d\.]+) MB\s+Rack: (.+)/)

        pid, mem, path = *match.captures
        next hash unless @options[:path].find {|p| path.match p}

        hash[pid.to_i] = {
          :mem  => mem.to_i,
          :path => path.strip
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
    command(PS_STATS) do |input, output|
      output.readlines.inject({}) do |hash, line|
        next hash unless match = line.match(/(\d+)\s+Rack: (.+)$/)
        pid, path = *match.captures

        next hash unless @options[:path].find {|p| path.match p}

        hash[pid.to_i] = { :path => path.strip }
        hash
      end
    end
  end

end

# Methods from this module will potentially be called when running this script,
# and they'll be executed in the order they are defined.
module CleanupActions

  # From http://www.modrails.com/documentation/Users%20guide%20Apache.html#debugging_frozen :
  #
  #   If one of your application instances is frozen (stopped responding), then
  #   you can figure out where it is frozen by killing it with SIGABRT. This
  #   will cause the application to raise an exception, with a backtrace.

  # Kill Rack processes that don't show up in passenger-status (though they
  # might show up in passenger-memory-stats).
  def zombies
    passenger_pids = passenger_status.keys
    zombies = ps_stats.delete_if do |pid|
      passenger_pids.include? pid
    end

    kill zombies, "Zombie", :SIGABRT
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

    kill stale, "Stale", :SIGABRT
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

    # Remove "catch all"-path regex if user supplied any.
    @options[:path].shift if @options[:path].size > 1

    puts %(Can't find any processes matching any of %s regular expressions!) % @options[:path].inspect unless ps_stats.size > 0

    @logs = @options[:tail].compact.map {|file| tail file }

    actions.each do |name|
      send name
    end

    @logs.each do |log|
      log.close
    end
  end

end

# Numbers are in megabytes or seconds.
defaults = {
  :fat     => 1024,
  :old     => 3600 * 24,
  :stale   => 3600
}

options = {
  :grace   => 30,
  :dry_run => false,
  :path    => [".+"],
  :tail    => []
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
  opts.separator "Extra output options:"

  opts.on("--tail=LOGFILE1,LOGFILE2", Array,
    "Tail LOGFILEs and copy output to standard out while running.") \
    {|a| options[:tail].concat a }

  opts.separator ""
  opts.separator "Common options:"

  opts.on("-pREGEX", "--path=REGEX1,REGEX2", Array,
    "Only touch processes matching REGEX path (#{options[:path].first}).") \
    {|s| options[:path].concat s }

  opts.on("-gSECONDS", "--grace SECONDS", Integer,
    "Give processes SECONDS (#{options[:grace]}) to die gracefully.") \
    {|i| options[:grace] = i }

  opts.on("-n", "--dry-run", "Don't actually kill processes.") { options[:dry_run] = true }
  opts.on("-h", "--help",    "Show this.")                     { puts opts; exit }

  options[:opts] = opts
end.parse!

PassengerJanitor.new(options).run
