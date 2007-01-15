# Copyright (C) 2007 Luca Filipozzi
# Copyright (C) 2007 Peter Palfrader

.PHONY: default
default: all

.PHONY: all
all: ip2ga.cidr

.PHONY: clean
clean:
	rm -f ip2iso.txt iso2ga.txt ip2ga.txt ip2ga.cidr

.PHONY: maintainer-clean
maintainer-clean: clean
	rm -f ip2iso.raw iso2ga.raw

.PHONY: force-update
force-update: maintainer-clean all

ip2iso.raw:
	rsync -rz countries-ns.mdc.dk::zone/zz.countries.nerd.dk.rbldnsd $@

iso2ga.raw:
	wget -q -O $@ 'http://en.wikipedia.org/wiki/List_of_countries_by_continent_(data_file)'

.INTERMEDIATE: ip2iso.txt
ip2iso.txt: ip2iso.raw
	tail -n +2 $< | sed -e 's#[[:space:]][[:space:]]*:[[:digit:].]*:# #' | awk '{print $$2, $$1}' | sort -t' ' -k1,1 > $@

# ensure that the following additional iso2ga mappings exist:
#  eu eu
#  uk eu
#  yu eu
# ensure that the geographic areas with no servers are mapped to zz:
#  af zz
#  as zz
#  sa zz
#  an zz
.INTERMEDIATE: iso2ga.txt
iso2ga.txt: iso2ga.raw
	grep -E "^AF|^AS|^EU|^NA|^SA|^AN|^OC" $< | awk '{print tolower($$2), tolower($$1)} END {printf "eu eu\nuk eu\nyu eu\n"}' | sed -e 's/ \(af\|as\|sa\|an\)$$/ zz/' | sort -t' ' -k1,1 > $@

# rely on 'join' to only join lines from the two files that match on the key
# but test that ip2iso.txt and ip2ga.txt are the same length just to be sure
.INTERMEDIATE: ip2ga.txt
ip2ga.txt: ip2iso.txt iso2ga.txt
	join $^ | cut -f2,3 -d' ' > $@
	@if test `cat $< | wc -l` -ne `cat $@ | wc -l`; then rm $@; exit 1; fi

# rely on 'sort -u' to sort two lines that match on the same field in the same order
# that they appear in the input stream with the result that exceptions are preferred
# but test that the count of exceptions in the output file and the count of them in
# the exceptions file are equal just to be sure
ip2ga.cidr: exceptions ip2ga.txt
	cat $^ | sort -u -t' ' -k1,1 > $@
	@if test `grep -c -F -f $< $@` -ne `cat $< | wc -l` ; then rm $@; exit 1; fi
