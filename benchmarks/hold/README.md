# "Hold" benchmarks

This benchmark mesures time spent on email processing between vSMTP and Postfix when receiving multiple messages at the same time and immediately holding them in their respective queues.

To reproduce the benchmarks of the root readme, simply add the content from the `vsmtp` directory in `/etc/vsmtp` and the configuration in the `postfix` directory in `/etc/postfix`.

> Do not forget to backup any existing configuration for both programs before copying the files.

In the readme benchmarks, we used `systemctl` to run postfix & vsmtp as services.

```sh
sudo systemctl start postfix.service
## or
sudo systemctl start vsmtp.service
```

> Before running any of the commands below, make sure that your Postix and vSMTP queues and log directory are empty. If not, make sur to make backups of those directories.

`smtp-source` is used to mesure the performances.

```sh
# smtp-source is included with postfix.
sudo apt install postfix
```

You can use the following command to simulate incoming clients.

```sh
time smtp-source -s <nbr-of-sessions>    \
                 -l <message-size>       \
                 -m <nbr-of-messages>    \
                 -f <sender-address>     \
                 -N                      \
                 -t <recipient-address>  \
                 127.0.0.1:25
```

For example:

```sh
time smtp-source -s 4 -l 1000000 -m 10000 -f john.doe@example.com -N -t jane.doe@example.com 127.0.0.1:25
```

Do not forget to empty all queues between each run of `smtp-source`, as they might clog up your filesystem really fast.

```sh
# Empty vsmtp's spool.
rm -rf /var/spool/vsmtp/

# Empty postfix's hold queue.
rm /var/spool/postfix/hold/*
```
