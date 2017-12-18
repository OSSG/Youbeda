# Youbeda

**Youbeda** is a Perl [OVZ](http://www.openvz.org/) complainer. It can look after VEs resources limits and make some actions on failcnt value increase. VEs to look after could be explicitly specified.

## Available actions:

* print notification (to stdout and/or logfile and/or syslog);
* send notification via email;
* send notification via Jabber;
* write complete statistics for exceeded resource into SQL database and/or SQLite and/or into file or pipe as plain SQL requests;
* adjust barrier and limit values for exceeded resources.

Unlike (dead?) Yabeda software **Youbeda** written in Perl and basically needs only core Perl modules. (However for some actions third-party Perl modules could be needed.)

Originally **Youbeda** was designed for [ALT Linux](http://www.altlinux.ru/) distros. But probably it can be used with any modern Linux distributions with OVZ-kernels.
