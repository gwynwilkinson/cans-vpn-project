/usr/lib/ssl/openssl.cnf edited so
policy = policy_anything
These values can be changed in our default config if we want to (discuss)

-------------------------------------------------------------------------------

mkdir demoCA
cd demoCA
mkdir certs
mkdir crl
touch index.txt serial
echo 1000 > serial

openssl req -x509 -newkey rsa:4096 -sha256 -days 1 -keyout vpn-key.pem -out vpn-cert.pem -nodes

Country Name (2 letter code) [AU]:GB
State or Province Name (full name) [Some-State]:Avon
Locality Name (eg, city) []:Bristol
Organization Name (eg, company) [Internet Widgits Pty Ltd]:UWE
Organizational Unit Name (eg, section) []:CSCT
Common Name (e.g. server FQDN or YOUR name) []:UWEVPN
Email Address []:gwyn2.wilkinson@live.uwe.ac.uk

----------------------------------------------------------------------------

openssl genrsa -out client-key.pem 4096

openssl req -new -key client-key.pem -out client.csr -sha256

Country Name (2 letter code) [AU]:GB
State or Province Name (full name) [Some-State]:Avon
Locality Name (eg, city) []:Bristol
Organization Name (eg, company) [Internet Widgits Pty Ltd]:UWE
Organizational Unit Name (eg, section) []:CSCT
Common Name (e.g. server FQDN or YOUR name) []:UWECLIENT
Email Address []:gwyn2.wilkinson@live.uwe.ac.uk

Please enter the following 'extra' attributes
to be sent with your certificate request
A challenge password []:password
An optional company name []:

-----------------------------------------------------------------------------

openssl ca -in client.csr -out client-cert.pem -md sha256 -cert vpn-cert.pem -keyfile vpn-key.pem -days 1
