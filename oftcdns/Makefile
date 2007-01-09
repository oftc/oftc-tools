.PHONY: all
all: geoip.cidr

clean:
	rm -f geoip.cidr geoip.raw

geoip.cidr: geoip.raw
	tail -n +2 $< | sed -e 's#:[[:digit:].]*:##' > $@

geoip.raw:
	rsync -rz countries-ns.mdc.dk::zone/zz.countries.nerd.dk.rbldnsd $@
