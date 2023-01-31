# TODO: send password and user by args.
# TODO: send database builder and scripts by args.
FROM viridit/vsmtp:v2.0.0

# Wait for vSMTP to be up and running.
RUN apk update && apk add curl
HEALTHCHECK --interval=5s --timeout=10s --start-period=10s \
    CMD curl -vv -k --url 'smtp://localhost:25'

# Symlink the plugin to our configuration.
RUN mkdir -p /etc/vsmtp/plugins/
RUN ln -s /usr/sbin/libvsmtp_plugin_mysql.so /etc/vsmtp/plugins/libvsmtp_plugin_mysql.so

CMD ["vsmtp" , "-c", "/etc/vsmtp/vsmtp.vsl", "--no-daemon", "--stdout"]
