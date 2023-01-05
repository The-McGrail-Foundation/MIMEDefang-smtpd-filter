MIMEDefang-smtpd-filter is an OpenSMTPD filter to integrate MIMEDefang and OpenSMTPD.

To enable the filter just add the following lines into your smtpd.conf:

    filter "mimedefang" proc-exec "filter-mimedefang.pl" user _mdefang group _mdefang
    listen on all filter "mimedefang"

The program has some parameters to modify its behavior.

-d enable debug mode, when debug mode is enabled, logs will be more
   verbose and temporary files under /var/spool/MIMEDefang will not be
   removed.

-H run helo checks by calling helo_check sub in mimedefang-filter(5)

-X Do not add an X-Scanned-By: header.

Some features that are available in MIMEDefang are not implemented.
In particular action_discard(), action_quarantine_entire_message(), add_recipient(),
delete_recipient() and change_sender() are not available.
