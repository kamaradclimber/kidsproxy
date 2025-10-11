Kidsproxy
---------


`kidsproxy` is a small HTTP proxy I use to enable internet access to my kids in a safe manner.

Most proxies allows access with carefully crafted denylists. This approach may work well for some but requires a strong confidence in those lists.

Instead I took the reverse stance: allow lists.

Each kid has a very small list of websites they are allowed to browse on.


How to run
----------

Launch it: `go build . && ./kidsproxy`

Then point your browser to use this proxy. Setup might be different for each browser.

How to configure it
-------------------

`kidsproxy` reads a configuration file in `/etc/kidsproxy/config.yaml`.

Commented example:
```
rules:
  kid1:
    - glob: home.familleseux.net # this is the configured homepage
    - glob:*.wikipedia.org # glob allow to allow multiple subdomains at once
    - glob:*.wikimedia.org
  kid2:
    - glob:*.lemonde.fr
  parents:
    - regexp:.*  # everything is allowed
  global: # global has a special meaning: rules are applied to every user
    - glob:*.mozilla.org
```

Firefox
-------

Firefox does not allow to authenticate against proxies without custom extensions.

- setup one proxy instance per kid session. Make sure the proxy runs with the `KIDSPROXY_FORCE_ACCOUNT` environment variable set to the kid name.
- Point each browser to a different port. 

This is the setup I'm using.

Security model
--------------

Here are the possibilities for a kid to bypass the proxy and how I've solved them.
- change browser configuration to not use the proxy -> firefox network configuration is locked using [policies](https://support.mozilla.org/en-US/kb/customizing-firefox-using-policiesjson), specifically by blocking proxy configuration
- use a different software to browse (like a built-in browser within an application) -> proxy configuration is passed using env variables such as `HTTP_PROXY`
- use a different software to browse after unsetting env variables -> DNS resolution is blocked for the laptop kids have access to (using pihole)

I'm assuming my kids are not technical enough yet to go beyond these limitations.

Of course, a technical savy user can escape this model easily:
- by using a different DNS server explicitely -> it does not require to be root, curl has all technical ways to do this

My security model is to protect my kids from browsing by mistake on untrusted websites. A sufficiently motivated kid can eventually escape this. I'll consider at this point they would have earnt enough maturity.

I'm also trusting my kids to discuss about what they do and see on the computer (and they already reported seeing disturbing articles on wikipedia for instance).


Features
--------

For now, this is a transparent proxy: it allows to filter domain names but does not observe/filter the rest of the traffic. Especially for https traffic.

Integration with datadog is builtin, mostly because I work there and it allows me to observe how the proxy is behaving.


Contributions & warranty
-------------

This proxy is a work-in-progress. I'm adding features when necessary.
This is not a parental control product but merely a tool I use.

You are welcome to use it, adapt it to your own needs and, if relevant, propose to contribute back.

Solving the use case exposed above is my primary concern.
