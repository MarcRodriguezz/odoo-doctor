# Stands in for an Odoo.sh build or a remote server: SSH, psql, tar, and nothing of Odoo itself.
FROM alpine:3.20
RUN apk add --no-cache openssh postgresql16-client tar bash coreutils \
 && adduser -D -s /bin/bash odoo \
 && passwd -u odoo \
 && ssh-keygen -A \
 && printf 'PermitUserEnvironment yes\nPasswordAuthentication no\nAllowUsers odoo\n' >> /etc/ssh/sshd_config
CMD ["/usr/sbin/sshd", "-D", "-e"]
