@			IN      SOA     dns.example.com. hostmaster.example.com. (
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
gns1			IN	A	127.0.0.1
gns2			IN	A	127.0.0.2
gns3			IN	A	127.0.0.3
gns4			IN	A	127.0.0.4
