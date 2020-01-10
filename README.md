# Nessus-Plugins

```
$ tar -cvzf dirsearch.tar.gz dirsearch.inc dirsearch.nasl
/opt/nessus/sbin/nessuscli fix --set nasl_no_signature_check=yes
# /opt/nessus/sbin/nessuscli update /home/user/dirsearch.tar.gz
# /opt/nessus/sbin/nessusd -t
```
Run plugin from command line
```
$ /opt/nessus/bin/nasl -t 192.168.1.1 dirsearch.nasl
```
