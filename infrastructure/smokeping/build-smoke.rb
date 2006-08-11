#!/usr/bin/ruby

# Copyright (C) 2006 by Joerg Jaspert <joerg@debian.org>
#
#    This program is free software; you can redistribute it and/or modify
#    it under the terms of the GNU General Public License as published by
#    the Free Software Foundation; either version 2 of the License, or
#    (at your option) any later version.
#
#    This program is distributed in the hope that it will be useful,
#    but WITHOUT ANY WARRANTY; without even the implied warranty of
#    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
#    GNU General Public License for more details.
#
#    You should have received a copy of the GNU General Public License
#    along with this script; if not, write to the Free Software
#    Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA

require "yaml"

config = YAML::load( File.open( 'servers.yaml' ) )
defaultconf = "smoke.default"

smokeconf = File.new("smoke.conf", "w")

File.open(defaultconf) do |file|
  file.each_line {|line| smokeconf.puts line}
end

a=config['servers'].sort_by {|x| [x["area"], x['name']] }

region=""

a.each do |server|
  smokeconf.puts "\n"

  if not server["area"] == region then
    smokeconf.puts "++#{server["area"]}"
    smokeconf.puts "menu = #{server["area"]}\n\n"
    region=server["area"]
  end
  smokeconf.puts "+++ #{server["name"]}"
  smokeconf.puts "menu = #{server["name"]}"
  smokeconf.puts "title = #{server["name"]}.oftc.net\n"
  smokeconf.puts "host = #{server["ip"]}"
end

