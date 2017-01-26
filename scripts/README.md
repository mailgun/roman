### Primer

Primer is an optional script that can be run on a host before using `roman`
within a service. `primer` has three main purposes:

* Request, download, and cache a TLS certificate out-of-band from a ACME server.
Getting a TLS certificate from an ACME server can take a few minutes and if the
initial certificate request is done in-band this could potentially cause
incoming request to fail. That's why the initial request is best done
out-of-band with `primer`. All subsequent requests for certificates are done 30
days before certificate expiration and occur in the background and do not block.

* Sanity check for certificates. Once `primer` downloads and caches a
certificate, it immediately starts a HTTPS server with the new TLS certificate.
You can use `curl` (see below) to test that the certificate and validate it
manually.

* Debugging `roman`. Since `primer` runs out of band and does the exact same
thing as a service using `roman`, it can be useful to add debug statements to
`roman` and rebuild `primer` and run it to see where the root cause of the
problem is.

#### Usage

1. If don't have DNS setup already, update `/etc/hosts` on the machine making
the request to point to the IP addresses of the server. For example, if your
server is `1.2.3.4` and you are requesting a certificate for `foo.example.com`,
add the following line to `/etc/hosts`:

        127.0.0.1 foo.example.com

1. Start `primer` on your server and use the command line flags to configure 
`primer`. Run `primer -h` for flag details. An example of typical usage would
be:

        $ sudo ./primer \
            -debug-mode="false" \
            -cache-path="/etc/companyName/serviceName/tls" \
            -configuration-path="/etc/companyName/serviceName/roman.configuration" \
            -hostname "foo.example.com"

1. Use `curl` to make a request to `primer`, you should see output like the
following if everything goes well:

        $ curl https://foo.example.com/url/path
        000001 Method: GET; URL: /url/path, ContentLength: 0

#### Debugging

Primer is a really useful script to use to debug issues with `roman`. You can
add log lines and the rebuilt `primer` can be used to figure out where the
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
            -configuration-path=".roman.configuration" \
            -hostname "foo.example.com"

1. Use `curl` to make a request to `primer`. Make sure you pass in the path to
the Let's Encrypt staging CA you downloaded in a previous step:

        $ curl --cacert ca.pem https://foo.example.com/url/path
        000001 Method: GET; URL: /url/path, ContentLength: 0
