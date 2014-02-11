fakeAP
======

Create a fake access point in Kali. Determines the correct DHCP settings and creates the dhcpd.conf file for you.


Usage
-----


``` shell
python fakeAP.py
```
Create a fake access point with the ESSID of 'Free Wifi' on channel 6 without encryption. 


``` shell
python fakeAP.py -t
```
-t, Sniff the air for all access points in range, Ctrl-C to select one and use its ESSID and channel in the creation of your fake AP.


``` shell
python fakeAP.py -c 1 -e 'New SSID' -w
```

-c, Start the access point on channel 1

-e, Set the broadcast ESSID as 'New SSID'

-w, Set the fake access point to use WPA2 flagged beacon frames and save handshakes to fakeAPlog.cap



-------
danmcinerney.org

[![Analytics](https://ga-beacon.appspot.com/UA-46613304-4/fakeAP/README.md)](https://github.com/igrigorik/ga-beacon)
