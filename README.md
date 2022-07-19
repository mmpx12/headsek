# HEADSEK: security header analyzer

![](.screenshot/github.png)
![](.screenshot/psg.png)

This tools analyse security headers based on OWASP Secure Headers Project,
 for more informations about security header go visit: https://owasp.org/www-project-secure-headers/

### Usage:

```
-h, --help                   Show this help
-d, --description            Print description under the result
-n, --nologo                 don't print banner
-k, --insecure               Ignore certificats issues
-u, --url=URL                set target URL (not mandatory if url is the last
                             parameter)
-U, --user-agent=USER-AGENT  set user-agent
-p, --post=POST-DATA         set post data (will use POST instead of GET)
-c, --cookies=COOKIES        set cookies
-H, --headers='NAME:VALUE'   set headers
-v, --version                show version
```

`-u` is not mandatory if the URL is the last argument.


### Examples:

```sh
# Simple GET request
$ headsek -n -u https://exemple.com

# POST request:
$ headsek -n -p "whatever=1&somethingelse=yes" https://exemple.com

# Set cookie and user-agent
$ headsek -n -c "sessionid=something;userid=1" -U "some user-agent" https://exemple.com

# Set custom header for request (usefull for api)
headsek -k -H 'Authorization: Token XXXXXXXXXXXXX' https://exemple.com
```


### Install:

```sh
git clone git@github.com:mmpx12/headsek.git
cd headsek
make
sudo make install
# or 
sudo make all
```
