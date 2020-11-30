# vhostsearch

Simple tool for checking vhost at ip range

## Why?

Cloudflare/Myracloud/... hides the ips of target systems. However you might have an idea in which range the real webserver is running. For this purpose
simply define the name of the vhost, define ips in the ip file and let the tool check if the vhost is defined at any of those webservers.

## Usage

./vhostsearch -t <vhost-name> -rf <file with ips one per line>

./vhostsearch -t maps.google.com -rf google-iprange.txt

## Fin
