# Anti-relaying

A simple set of rules to setup anti relaying with vsl. vSMTP, by it's configuration architecture, implicitly handles anti-relaying:

```
/etc/vsmtp
┣ vsmtp.vsl
┣ conf.d/
┃     ┗ config.vsl
┣ domain-available/
┃     ┣ main.vsl            # -> auth
┃     ┣ fallback.vsl        # -> decide anti-relaying procedure
┃     ┗ example.com/
┃          ┣ incoming.vsl
┃          ┣ outgoing.vsl
┃          ┗ internal.vsl
┗ objects/
      ┗ net.vsl
```

In this example, if:

- The sender's domain is not 'example.com' and a recipient IS NOT 'example.com' as well, this is relaying, thus the `fallback.vsl` script is called, denying the connexion.
- The sender's domain is not 'example.com' and a recipient's domain IS 'example.com', then the `example.com/incoming.vsl` script is called. In this example, we allow only one server to send messages to 'example.com'.
- The sender's domain is 'example.com', the `example.com/internal.vsl` script is called if the recipient's domain is 'example.com', otherwise `example.com/outgoing.vsl` is called.

As you can see, using the `main.vsl` & `fallback.vsl` scripts, it is easy to decide what to do when a server tries to use yours as an open relay. In `fallback.vsl`, a simple `deny` is used, but you could add the address to a greylist, simply remove the recipients from the envelop, or report the IP as spam.
