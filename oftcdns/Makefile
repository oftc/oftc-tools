# Copyright (C) 2007 Luca Filipozzi
# Copyright (C) 2007 Peter Palfrader

.PHONY: default
default: all

.PHONY: all
all: ip2region.cidr

.PHONY: clean
clean:
	rm -f ip2iso.txt iso2region.txt ip2region.txt ip2region.cidr

.PHONY: maintainer-clean
maintainer-clean: clean
	rm -f ip2iso.raw iso2region.raw

.PHONY: force-update
force-update: maintainer-clean all

ip2iso.raw:
	wget -q -O $@ http://bgp.potaroo.net/stats/nro/delegated.nro.txt

iso2region.raw:
	wget -q -O $@ http://download.geonames.org/export/dump/countryInfo.txt

#.INTERMEDIATE: ip2iso.txt
ip2iso.txt: ip2iso.raw
	tail -n +5 $< | grep -F '|ipv4|' | grep -E 'assigned$$|allocated$$' | awk -F '|' '{print $$2, $$4, $$5}' | ./mkcidrs | sort -t' ' -k1,1 > $@

# ensure that the following additional iso2region mappings exist:
#  ap as
#  eu eu
#  uk eu
#  yu eu
# ensure that the geographic areas with no servers are mapped to global:
#  af global
#  as global
#  sa global
#  an global
#.INTERMEDIATE: iso2region.txt
iso2region.txt: iso2region.raw
	tail -n +2 $< | cut -f1,9 -d'	' | awk '{print tolower($$1), tolower($$2)} END {printf "ap as\neu eu\nuk eu\nyu eu\n"}' | sed -e 's/ \(af\|as\|sa\|an\)$$/ global/' | sort -u -t' ' -k1,1 > $@

# rely on 'join' to only join lines from the two files that match on the key
# but test that ip2iso.txt and ip2region.txt are the same length just to be sure
#.INTERMEDIATE: ip2region.txt
ip2region.txt: ip2iso.txt iso2region.txt
	join $^ | cut -f2,3 -d' ' > $@
	@if test `cat $< | wc -l` -ne `cat $@ | wc -l`; then rm $@; exit 1; fi

# rely on 'sort -u' to sort two lines that match on the same field in the same order
# that they appear in the input stream with the result that exceptions are preferred
# but test that the count of exceptions in the output file and the count of them in
# the exceptions file are equal just to be sure
ip2region.cidr: exceptions ip2region.txt
	cat $^ | sort -u -t' ' -k1,1 | ./aggregate > $@
	@if test `grep -c -F -f $< $@` -ne `cat $< | wc -l` ; then rm $@; exit 1; fi
