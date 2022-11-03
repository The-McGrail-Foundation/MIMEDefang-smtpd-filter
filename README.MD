MIMEDefang-smtpd-filter is an OpenSMTPD filter to integrate MIMEDefang and OpenSMTPD.

To enable the filter just add the following lines into your smtpd.conf:

    filter "mimedefang" proc-exec "filter-mimedefang.pl" user _mdefang group _mdefang
    listen on all filter "mimedefang"

The program has a "-d" parameter to enable debug mode, when debug mode is enabled, logs will
be more verbose and temporary files under /var/spool/MIMEDefang will not be removed.
