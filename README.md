fakeAP
======

Create a fake access point in Kali. Determines the correct DHCP settings and creates the dhcpd.conf file for you.


Usage
-----


``` shell
python fakeAP.py
```
This will create a soft access point with the ESSID of 'Free Wifi' on channel 6 without encryption. 


``` shell
python fakeAP.py -c 1 -e 'New SSID'
```

-c, Start the access point on channel 1

-e, Set the broadcast ESSID as 'New SSID'



-------
danmcinerney.org

[![Analytics](https://ga-beacon.appspot.com/UA-46613304-4/fakeAP/README.md)](https://github.com/igrigorik/ga-beacon)
