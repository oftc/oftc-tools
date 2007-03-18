@			IN      SOA     dns.geo.example.com. hostmaster.geo.example.com. (
				2007020600      ; Serial YYYYMMDD##
				1h              ; Refresh
				5m              ; Retry
				2w              ; Expire
				30m )           ; Negative Cache TTL
$TTL 7d
			IN      NS      gns1.geo.example.com.
			IN      NS      gns2.geo.example.com.
			IN      NS      gns3.geo.example.com.
			IN      NS      gns4.geo.example.com.
