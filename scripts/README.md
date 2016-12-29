### Primer

Primer is an optional script that can be run on a host before using `roman`
within your web server. `primer` can download and place the requested
certificate in the passed in cache directory so that initial startup time for
your processes is near zero.

#### Usage

1. If don't have DNS setup already, update `/etc/hosts` on the machine making
the request to point to the IP addresses of the server. For example, if your
server is `1.2.3.4` and you are requesting a certificate for `foo.example.com`,
add the following line to `/etc/hosts`:

        127.0.0.1 foo.example.com

1. Start `primer` on your server and use the command line flags to pass in
`cache-path` (where your server will be looking for certificates to be cached),
`configuration-path` (this is where you store the `.roman.configuration` secrets
needed to connect to a challenge performer), `hostname` (the host for which
you are trying to get a certificate), and `debug-mode` (contact production Let's
Encrypt servers). An example:

        $ sudo ./primer \
            -debug-mode="false" \
            -cache-path="/etc/roman/cache" \
            -configuration-path="/etc/roman/configuration/roman.configuration" \
            -hostname "foo.example.com"

1. Use `curl` to make a request to `primer`, you should see output like the
following if everything goes well:

        $ curl https://foo.example.com/url/path
        Method: GET; URL: /url/path, ContentLength: 0

#### Debugging

Primer is a really useful script to use to debug issues with `roman`. You can
add log lines and the rebuild `primer` can be used to figure out where the
problem is. To set up `primer` in debugging more, you need to do a few things:

1. Update `roman` source code and rebuild `primer`:

        $ go build primer.go

1. Update `/etc/hosts` so the hostname for which the certificates you are
requesting points to localhost. You can do that by updating `/etc/hosts` like
so:

        127.0.0.1 foo.example.com

1. Run the following command from a terminal window. Copy the certificate to a
file called `ca.pem`.

        $ curl http://cert.stg-root-x1.letsencrypt.org/ | openssl x509 -inform der -outform pem -text

1. Start the `primer` server:

        $ sudo ./primer \
            -debug-mode="true" \
            -cache-path="." \
            -configuration-path="../.roman.configuration" \
            -hostname "foo.example.com"

1. Use `curl` to make a request to `primer`. Make sure you pass in the path to
the Let's Encrypt staging CA you downloaded in a previous step:

        $ curl --cacert ca.pem https://foo.example.com/url/path
        Method: GET; URL: /url/path, ContentLength: 0


