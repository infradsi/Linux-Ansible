#!/bin/bash
# Profil ciblé : CIS Red Hat Enterprise Linux 8 (Server L1) – testé sur RHEL 8.10
# Remarque : les numéros de sections font référence au benchmark RHEL 8.x (v2.x+).
# Certaines organisations utilisent des annexes différentes ; adaptez au besoin.
# NOTE IMPORTANTE (CIS): Les identifiants ci‑dessous se réfèrent aux Benchmarks CIS RHEL/Rocky 8/9 (Server L1) les plus courants.
# Selon la version exacte du benchmark, certains numéros/titres peuvent légèrement varier. Ils servent ici de repères pour compréhension.

AUDITDIR="/tmp/$(hostname -s)_audit"
TIME="$(date +%F_%T)"
. /etc/os-release
MAIN_VERSION_ID="$(echo ${VERSION_ID} |cut -f1 -d'.')"
if [[ ${MAIN_VERSION_ID} -lt 8 ]]; then
  echo "OS release lower than 8 not supported. You are running ${VERSION_ID}"
fi

mkdir -p $AUDITDIR

# CIS 1.1.1.x – Désactiver le montage des systèmes de fichiers non requis (cramfs, squashfs, udf, hfs, hfsplus, jffs2, vfat…)
# (Réduction de surface d’attaque via modprobe install /bin/true)
# Impact: peut empêcher montage USB (vfat), images ISO (udf), paquets squashfs; prévoir exceptions si nécessaires.
echo "Disabling Legacy Filesystems"
cat > /etc/modprobe.d/CIS.conf << "EOF"
install cramfs /bin/true
install freevxfs /bin/true
install jffs2 /bin/true
install hfs /bin/true
install hfsplus /bin/true
install squashfs /bin/true
install vfat /bin/true
install udf /bin/true
install dccp /bin/true
install sctp /bin/true
install rds /bin/true
install tipc /bin/true
install usb-storage /bin/true
EOF

# CIS 1.8 – Supprimer les compilateurs (sur RHEL7 c'était 1.9) – conserver uniquement si non requis en prod sur systèmes de prod si non requis
# (gcc facilite la compilation de code potentiellement malveillant)
# Impact: empêche compilation locale (DKMS/modules/agents); à éviter sur hôtes build ou pilotes propriétaires.
echo "Removing GCC compiler..."
yum -y remove gcc*

# CIS 2.1.x/2.2.x – Supprimer/Désactiver les services hérités et à risque (rsh, yp, tftp, talk, telnet, xinetd)
# Impact: coupe rsh/yp/tftp/talk/telnet/xinetd s'ils étaient encore utilisés (legacy PXE, admin, NIS).
echo "Removing legacy services..."
yum -y remove rsh-server rsh ypserv tftp tftp-server talk talk-server telnet-server xinetd >> $AUDITDIR/service_remove_$TIME.log

# CIS 2.2.x – Désinstaller LDAP (serveur/clients) si non utilisé
# Impact: supprime openldap serveur/clients; peut casser intégrations/tests LDAP locaux.
echo "Disabling LDAP..."
yum -y remove openldap-servers >> $AUDITDIR/service_remove_$TIME.log
yum -y remove openldap-clients >> $AUDITDIR/service_remove_$TIME.log

# CIS 2.2.x – Désinstaller les services réseau non requis (bind, vsftpd, dovecot, samba, squid, net-snmp)
# Impact: arrêt DNS local, SMB, FTP, IMAP, Proxy, SNMP si utilisés en prod.
echo "Remove Bind, vsftp, Dovecot, Samba, Squid, net-snmp..."
yum -y remove bind vsftpd dovecot samba squid net-snmp >> $AUDITDIR/service_remove_$TIME.log

# CIS 5.5.4 (parfois 5.5.5/5.5.x selon versions) – Définir umask par défaut plus restrictif pour les démons
# (Ici via /etc/init.d/functions – impacte les services hérités) 
# Impact: fichiers de service créés en 027 → possible régression si applis attendent des droits plus ouverts.
echo "Setting Daemon umask..."
sed -i -E 's/umask [0-9]+/umask 027/g' /etc/init.d/functions

# CIS 2.2.x – Désactiver les services non nécessaires (systemd)
# Impact: désactivation dhcpd/avahi/cups/nfs*/rpc* peut interrompre DHCP, impression, montages NFS.
echo "Disabling Unnecessary Services..."
servicelist=(dhcpd avahi-daemon cups nfslock rpcgssd rpcbind rpcidmapd rpcsvcgssd)
for i in ${servicelist[@]}; do
  [ $(systemctl disable $i 2> /dev/null) ] || echo "$i is Disabled"
done

# CIS 5.5.1.x – Qualité des mots de passe (pwquality)
#  • 5.5.1.1 minlen >= 14
#  • 5.5.1.2/3/4 ucredit/dcredit/ocredit/lcredit = -1
#  • 5.5.1.5 retry = 3
# Impact: durcissement pwquality peut bloquer des changements de mot de passe non conformes.
echo "Setting Password Quality policies..."
for i in \
"minlen = 14" \
"dcredit = -1" \
"ucredit = -1" \
"ocredit = -1" \
"lcredit = -1" \
"retry = 3" \
; do
  [[ `grep -q "^$i" /etc/security/pwquality.conf` ]] && continue
  option=${i%%=*}
  if [[ `grep -q "${option}" /etc/security/pwquality.conf` ]]; then
    sed -i "s/.*${option}.*/$i/g" /etc/security/pwquality.conf
  else
    echo "${i}" >> /etc/security/pwquality.conf
  fi
done

# CIS 4.2.1.x – Configuration de systemd-journald (Storage=persistent, Compress, ForwardToSyslog) sur RHEL 8
# Impact: Storage=persistent accroît l'usage disque; ForwardToSyslog exige rsyslog; surveiller la rotation.
echo "Setting journald configuration"
for i in \
"Compress=yes" \
"ForwardToSyslog=yes" \
"Storage=persistent" \
; do
  [[ `grep -q "^$i" /etc/systemd/journald.conf` ]] && continue
  option=${i%%=*}
  if [[ `grep "${option}" /etc/systemd/journald.conf` ]]; then
    sed -i "s/.*${option}.*/$i/g" /etc/systemd/journald.conf
  else
    echo "${i}" >> /etc/systemd/journald.conf
  fi
done

# CIS 1.5.1/1.5.2 – Désactiver/contrôler les core dumps (limites)
# Impact: désactive les core dumps → débogage post‑incident plus difficile.
echo "Setting core dump security limits..."
echo '* hard core 0' > /etc/security/limits.conf

# CIS 4.2.2.x – rsyslog : fichiers de config dédiés et permissions restrictives
# (CIS recommande au minimum 0640 sur les logs; ici 600 sur le .conf)
# Impact: changement permissions/flux rsyslog; risque d'incompatibilité avec collecteurs existants.
echo "Generating additional logs..."
echo '$FileCreateMode 0640' > /etc/rsyslog.d/CIS.conf
echo 'auth /var/log/secure' >> /etc/rsyslog.d/CIS.conf
echo 'kern.* /var/log/messages' >> /etc/rsyslog.d/CIS.conf
echo 'daemon.* /var/log/messages' >> /etc/rsyslog.d/CIS.conf
echo 'syslog.* /var/log/messages' >> /etc/rsyslog.d/CIS.conf
chmod 600 /etc/rsyslog.d/CIS.conf

# CIS 4.1.1.2 – S'assurer que le service auditd est activé
# Impact: léger overhead I/O/CPU; nécessaire avant règles strictes.
echo "Enabling auditd service..."
systemctl enable auditd

# CIS 4.1.2.x – Paramétrer l'espace/rotation d'auditd (space_left_action, action_mail_acct, admin_space_left_action, keep_logs)
# Impact: 'admin_space_left_action = halt' peut arrêter la machine si disque plein; 'keep_logs' peut saturer le FS.
echo "Configuring Audit Log Storage Size..."
cp -a /etc/audit/auditd.conf /etc/audit/auditd.conf.bak
sed -i 's/^space_left_action.*$/space_left_action = email/' /etc/audit/auditd.conf
sed -i 's/^action_mail_acct.*$/action_mail_acct = root/' /etc/audit/auditd.conf
sed -i 's/^admin_space_left_action.*$/admin_space_left_action = halt/' /etc/audit/auditd.conf
sed -i 's/^max_log_file_action.*$/max_log_file_action = keep_logs/' /etc/audit/auditd.conf

# CIS 4.1.3.x & 4.1.4.x – Règles d'audit essentielles (time-change, identity, locale, logins, session,
#  modifications permissions, accès refusés, montages, suppressions, sudoers, modules, SELinux, immutabilité)
# Impact: plus de logs et overhead; '-e 2' rend les règles immuables jusqu'au reboot.
echo "Setting audit rules..."
cat > /etc/audit/rules.d/CIS.rules << "EOF"
-D
-b 320

-a always,exit -F arch=b64 -S adjtimex -S settimeofday -k time-change
-a always,exit -F arch=b32 -S adjtimex -S settimeofday -S stime -k time-change
-a always,exit -F arch=b64 -S clock_settime -k time-change
-a always,exit -F arch=b32 -S clock_settime -k time-change
-w /etc/localtime -p wa -k time-change

-w /etc/group -p wa -k identity
-w /etc/passwd -p wa -k identity
-w /etc/gshadow -p wa -k identity
-w /etc/shadow -p wa -k identity
-w /etc/security/opasswd -p wa -k identity

-a always,exit -F arch=b64 -S sethostname -S setdomainname -k system-locale
-a always,exit -F arch=b32 -S sethostname -S setdomainname -k system-locale
-w /etc/issue -p wa -k system-locale
-w /etc/issue.net -p wa -k system-locale
-w /etc/hosts -p wa -k system-locale
-w /etc/sysconfig/network -p wa -k system-locale

-w /var/log/faillog -p wa -k logins
-w /var/log/lastlog -p wa -k logins
-w /var/log/tallylog -p wa -k logins

-w /var/run/utmp -p wa -k session
-w /var/log/wtmp -p wa -k session
-w /var/log/btmp -p wa -k session

-a always,exit -F arch=b64 -S chmod -S fchmod -S fchmodat -F auid>=1000 -F auid!=4294967295 -k perm_mod
-a always,exit -F arch=b32 -S chmod -S fchmod -S fchmodat -F auid>=1000 -F auid!=4294967295 -k perm_mod
-a always,exit -F arch=b64 -S chown -S fchown -S fchownat -S lchown -F auid>=1000 -F auid!=4294967295 -k perm_mod
-a always,exit -F arch=b32 -S chown -S fchown -S fchownat -S lchown -F auid>=1000 -F auid!=4294967295 -k perm_mod
-a always,exit -F arch=b64 -S setxattr -S lsetxattr -S fsetxattr -S removexattr -S lremovexattr -S fremovexattr -F auid>=1000 -F auid!=4294967295 -k perm_mod
-a always,exit -F arch=b32 -S setxattr -S lsetxattr -S fsetxattr -S removexattr -S lremovexattr -S fremovexattr -F auid>=1000 -F auid!=4294967295 -k perm_mod

-a always,exit -F arch=b64 -S creat -S open -S openat -S truncate -S ftruncate -F exit=-EACCES -F auid>=1000 -F auid!=4294967295 -k access
-a always,exit -F arch=b32 -S creat -S open -S openat -S truncate -S ftruncate -F exit=-EACCES -F auid>=1000 -F auid!=4294967295 -k access
-a always,exit -F arch=b64 -S creat -S open -S openat -S truncate -S ftruncate -F exit=-EPERM -F auid>=1000 -F auid!=4294967295 -k access
-a always,exit -F arch=b32 -S creat -S open -S openat -S truncate -S ftruncate -F exit=-EPERM -F auid>=1000 -F auid!=4294967295 -k access

-a always,exit -F arch=b64 -S mount -F auid>=1000 -F auid!=4294967295 -k mounts
-a always,exit -F arch=b32 -S mount -F auid>=1000 -F auid!=4294967295 -k mounts

-a always,exit -F arch=b64 -S unlink -S unlinkat -S rename -S renameat -F auid>=1000 -F auid!=4294967295 -k delete
-a always,exit -F arch=b32 -S unlink -S unlinkat -S rename -S renameat -F auid>=1000 -F auid!=4294967295 -k delete

-w /etc/sudoers -p wa -k scope

-w /var/log/sudo.log -p wa -k actions

-w /sbin/insmod -p x -k modules
-w /sbin/rmmod -p x -k modules
-w /sbin/modprobe -p x -k modules
-a always,exit -F arch=b64 -S init_module -S delete_module -k modules

-w /etc/selinux/ -p wa -k MAC-policy

-e 2
EOF
echo "Generating audit rules..."
augenrules

# CIS 5.1.x – Cron/Anacron présents, crond activé, permissions des crons strictes
# Impact: permissions strictes sur cron peuvent surprendre certains paquets/scripts.
echo "Configuring Cron and Anacron..."
yum -y install cronie-anacron >> $AUDITDIR/service_install_$TIME.log
systemctl enable crond
for i in anacrontab crontab cron.hourly cron.daily cron.weekly cron.monthly; do
  chown root:root /etc/$i
  chmod 600 /etc/$i
done
chmod 700 /etc/cron.d

# CIS 5.1.8/5.1.9 – at/cron allow/deny (n'autoriser que via *.allow et supprimer *.deny)
# Impact: seuls les utilisateurs listés dans *.allow pourront utiliser at/cron; risque de blocage de tâches existantes.
echo "Handle At and Cron Allow Files..."
for file in at cron; do
  touch /etc/${file}.allow
  chown root:root /etc/${file}.allow
  chmod 600 /etc/${file}.allow
  rm -rf /etc/${file}.deny
done

# CIS 1.7.1.x – Bannières légales (/etc/issue, /etc/issue.net, /etc/motd) sur RHEL 8
# Impact: remplace issue/motd; impact fonctionnel faible mais peut masquer messages internes.
echo "Creating Banner..."
sed -i "s/\#Banner none/Banner \/etc\/issue\.net/" /etc/ssh/sshd_config
cp -p /etc/issue.net $AUDITDIR/issue.net_$TIME.bak
cat > /etc/issue.net << 'EOF'
/------------------------------------------------------------------------\
|                       *** NOTICE TO USERS ***                          |
|                                                                        |
| This computer system is the private property of YOUR_COMPANY_NAME      |
| It is for authorized use only.                                         |
|                                                                        |
| Users (authorized or unauthorized) have no explicit or implicit        |
| expectation of privacy.                                                |
|                                                                        |
| Any or all uses of this system and all files on this system may be     |
| intercepted, monitored, recorded, copied, audited, inspected, and      |
| disclosed to your employer, to authorized site, government, and law    |
| enforcement personnel, as well as authorized officials of government   |
| agencies, both domestic and foreign.                                   |
|                                                                        |
| By using this system, the user consents to such interception,          |
| monitoring, recording, copying, auditing, inspection, and disclosure   |
| at the discretion of such personnel or officials.  Unauthorized or     |
| improper use of this system may result in civil and criminal penalties |
| and administrative or disciplinary action, as appropriate. By          |
| continuing to use this system you indicate your awareness of and       |
| consent to these terms and conditions of use. LOG OFF IMMEDIATELY if   |
| you do not agree to the conditions stated in this warning.             |
\------------------------------------------------------------------------/
EOF
cp -p /etc/motd /etc/motd_$TIME.bak
cat > /etc/motd << 'EOF'
YOUR_COMPANY_NAME AUTHORIZED USE ONLY
EOF
rm -rf /etc/issue
ln -s /etc/issue.net /etc/issue

# CIS 5.2.x – Configuration SSH sécurisée (boucle multi‑paramètres). Mapping rapide RHEL 8 :
#  • 5.2.2 LogLevel INFO
#  • 5.2.3 MaxAuthTries 4
#  • 5.2.4 IgnoreRhosts yes
#  • 5.2.5 HostbasedAuthentication no
#  • 5.2.7 PermitRootLogin no
#  • 5.2.8 PermitEmptyPasswords no
#  • 5.2.9 PermitUserEnvironment no
#  • 5.2.13 ClientAliveInterval/CountMax
#  • 5.2.14 LoginGraceTime 60
#  • 5.2.15 UsePAM yes
#  • 5.2.16 AllowTcpForwarding no
#  • 5.2.18 Ciphers sûrs
#  (Protocol 2 est implicite sur RHEL 8 mais conservé à titre explicite)
# MaxAuthTries 4, IgnoreRhosts yes, HostbasedAuthentication no, PermitRootLogin no, PermitEmptyPasswords no,
# PermitUserEnvironment no, ClientAliveInterval/CountMax, LoginGraceTime, UsePAM yes, MaxStartups, AllowTcpForwarding no,
# Ciphers sûrs)
# Impact: 'PermitRootLogin no' exige sudo OK; 'AllowTcpForwarding no' casse tunnels; ciphers restreints → incompatibilité vieux clients; restart sshd peut couper la session.
echo "Configuring SSH..."
cp /etc/ssh/sshd_config $AUDITDIR/sshd_config_$TIME.bak
for i in \
"LogLevel INFO" \
"Protocol 2" \
"X11Forwarding no" \
"MaxAuthTries 4" \
"IgnoreRhosts yes" \
"HostbasedAuthentication no" \
"PermitRootLogin no" \
"PermitEmptyPasswords no" \
"PermitUserEnvironment no" \
"ClientAliveInterval 300" \
"ClientAliveCountMax 0" \
"LoginGraceTime 60" \
"UsePAM yes" \
"MaxStartups 10:30:60" \
"AllowTcpForwarding no" \
"Ciphers aes128-ctr,aes192-ctr,aes256-ctr" \
; do
  [[ `egrep -q "^${i}" /etc/ssh/sshd_config` ]] && continue
  option=${i%% *}
  grep -q ${option} /etc/ssh/sshd_config && sed -i "s/.*${option}.*/$i/g" /etc/ssh/sshd_config || echo "$i" >> /etc/ssh/sshd_config
done

# CIS 5.2.1 – Propriétaire root et permissions 600 sur /etc/ssh/sshd_config
chown root:root /etc/ssh/sshd_config
chmod 600 /etc/ssh/sshd_config

systemctl restart sshd >> $AUDITDIR/service_restart_$TIME.log

# CIS 5.5.4 – umask par défaut des shells utilisateurs à 027 (plus restrictif que 022)
# Impact: umask 027 pour les shells utilisateurs peut gêner partages; prévoir groupes/ACL.
echo "Setting default umask for users..."
line_num=$(grep -n "^[[:space:]]*umask" /etc/bashrc | head -1 | cut -d: -f1)
sed -i ${line_num}s/002/027/ /etc/bashrc
line_num=$(grep -n "^[[:space:]]*umask" /etc/profile | head -1 | cut -d: -f1)
sed -i ${line_num}s/002/027/ /etc/profile

# (Hors périmètre CIS strict) – Historisation shell : horodatage et taille d'historique accrue
# Impact: mineur (stockage historique accru); utile pour traçabilité.
echo "Set History Timestamp for all users..."
grep -q "HISTTIMEFORMAT=" /etc/profile || echo "export HISTTIMEFORMAT=\"%d.%m.%y %T  \"" >> /etc/profile

# Impact: mineur (historique plus volumineux).
echo "Set History size..."
sed -i -E 's/^HISTSIZE.*/HISTSIZE=10000/g' /etc/profile

# CIS 5.5.2 – Verrouillage des comptes inactifs après 30 jours
# Impact: peut verrouiller des comptes rarement utilisés (service/maintenance). Surveillez les exceptions.
echo "Locking inactive user accounts..."
useradd -D -f 30

# CIS 5.5.3/5.5.4/5.5.5 – Politiques de mot de passe (max/min/warn)
# Impact: rotations de mots de passe plus fréquentes; PASS_MIN_DAYS 7 empêche changement immédiat après réinitialisation.
echo "Set login.defs..."
for i in \
"PASS_MAX_DAYS 90" \
"PASS_MIN_DAYS 7" \
"PASS_WARN_AGE 7" \
; do
  [[ `egrep "^${i}" /etc/login.defs` ]] && continue
  option=${i%% *}
  grep -q ${option} /etc/login.defs && sed -i "s/.*${option}.*/$i/g" /etc/login.defs || echo "$i" >> /etc/login.defs
done

# CIS 6.1.x – Permissions des fichiers critiques du système (/etc/passwd, shadow, group, gshadow, grub, rsyslog)
# Impact: durcit les droits; grub.cfg 600 peut perturber certains outils d'update bootloader.
echo "Verifying System File Permissions..."
chmod 644 /etc/passwd
chmod 000 /etc/shadow
chmod 000 /etc/gshadow
chmod 644 /etc/group
# grub.cfg won't exist on an EFI system
if [ -f /boot/grub2/grub.cfg ]; then
	chmod 600 /boot/grub2/grub.cfg
fi
chmod 600 /etc/rsyslog.conf
chown root:root /etc/passwd
chown root:root /etc/shadow
chown root:root /etc/gshadow
chown root:root /etc/group

# CIS 6.1.12 – Activer le sticky bit sur tous les répertoires world‑writable
# Impact: faible; recommandé pour protéger les répertoires partagés.
echo "Setting Sticky Bit on All World-Writable Directories..."
df --local -P | awk {'if (NR!=1) print $6'} | xargs -I '{}' find '{}' -xdev -type d \( -perm -0002 -a ! -perm -1000 \) 2>/dev/null | xargs -r chmod a+t >> $AUDITDIR/sticky_on_world_$TIME.log

# CIS 6.1.10/6.1.11/6.1.13/6.1.14 – Recherches d'objets à risque (world-writable, sans owner/groupe, SUID/SGID)
echo "Searching for world writable files..."
df --local -P | awk {'if (NR!=1) print $6'} | xargs -I '{}' find '{}' -xdev -type f -perm -0002 >> $AUDITDIR/world_writable_files_$TIME.log

echo "Searching for Un-owned files and directories..."
df --local -P | awk {'if (NR!=1) print $6'} | xargs -I '{}' find '{}' -xdev -nouser -ls >> $AUDITDIR/unowned_files_$TIME.log

# CIS 6.1.11 – Fichiers/répertoires sans groupe
echo "Searching for Un-grouped files and directories..."
df --local -P | awk {'if (NR!=1) print $6'} | xargs -I '{}' find '{}' -xdev -nogroup -ls >> $AUDITDIR/ungrouped_files_$TIME.log

# CIS 6.1.13 – Binaires SUID
echo "Searching for SUID System Executables..."
df --local -P | awk {'if (NR!=1) print $6'} | xargs -I '{}' find '{}' -xdev -type f -perm -4000 -print >> $AUDITDIR/suid_exec_$TIME.log

# CIS 6.1.14 – Binaires SGID
echo "Searching for SGID System Executables..."
df --local -P | awk {'if (NR!=1) print $6'} | xargs -I '{}' find '{}' -xdev -type f -perm -2000 -print >> $AUDITDIR/sgid_exec_$TIME.log

# CIS 5.4.3 – Aucune entrée de mot de passe vide
echo "Searching for empty password fields..."
/bin/cat /etc/shadow | /bin/awk -F: '($2 == "" ) { print $1 " does not have a password "}' >> $AUDITDIR/empty_passwd_$TIME.log

# CIS 6.2.x – Revue comptes et groupes (entrées '+', UID 0 unique, etc.)
echo "Reviewing User and Group Settings..."
echo "Reviewing User and Group Settings..." >> $AUDITDIR/reviewusrgrp_$TIME.log
/bin/grep '^+:' /etc/passwd >> $AUDITDIR/reviewusrgrp_$TIME.log
/bin/grep '^+:' /etc/shadow >> $AUDITDIR/reviewusrgrp_$TIME.log
/bin/grep '^+:' /etc/group >> $AUDITDIR/reviewusrgrp_$TIME.log
/bin/cat /etc/passwd | /bin/awk -F: '($3 == 0) { print $1 }' >> $AUDITDIR/reviewusrgrp_$TIME.log

# CIS 6.2.5 – Intégrité du PATH de root (pas de '.', pas de répertoires world/group‑writable, owned by root)
echo "Checking root PATH integrity..."

if [ "`echo $PATH | /bin/grep :: `" != "" ]; then
    echo "Empty Directory in PATH (::)" >> $AUDITDIR/root_path_$TIME.log
fi

if [ "`echo $PATH | /bin/grep :$`"  != "" ]; then
    echo "Trailing : in PATH" >> $AUDITDIR/root_path_$TIME.log
fi

p=`echo $PATH | /bin/sed -e 's/::/:/' -e 's/:$//' -e 's/:/ /g'`
set -- $p
while [ "$1" != "" ]; do
    if [ "$1" = "." ]; then
        echo "PATH contains ." >> $AUDITDIR/root_path_$TIME.log
        shift
        continue
    fi
    if [ -d $1 ]; then
        dirperm=`/bin/ls -ldH $1 | /bin/cut -f1 -d" "`
        if [ `echo $dirperm | /bin/cut -c6 ` != "-" ]; then
            echo "Group Write permission set on directory $1" >> $AUDITDIR/root_path_$TIME.log
        fi
        if [ `echo $dirperm | /bin/cut -c9 ` != "-" ]; then
            echo "Other Write permission set on directory $1" >> $AUDITDIR/root_path_$TIME.log
        fi
            dirown=`ls -ldH $1 | awk '{print $3}'`
           if [ "$dirown" != "root" ] ; then
             echo "$1 is not owned by root" >> $AUDITDIR/root_path_$TIME.log
              fi
    else
            echo "$1 is not a directory" >> $AUDITDIR/root_path_$TIME.log
      fi
    shift
done

# CIS 6.2.7/6.2.8/6.2.9 – Permissions et présence des répertoires home utilisateurs
echo "Checking Permissions on User Home Directories..."

for dir in `/bin/cat /etc/passwd  | /bin/egrep -v '(root|halt|sync|shutdown)' |\
    /bin/awk -F: '($8 == "PS" && $7 != "/sbin/nologin") { print $6 }'`; do
        dirperm=`/bin/ls -ld $dir | /bin/cut -f1 -d" "`
        if [ `echo $dirperm | /bin/cut -c6 ` != "-" ]; then
            echo "Group Write permission set on directory $dir" >> $AUDITDIR/home_permission_$TIME.log
        fi
        if [ `echo $dirperm | /bin/cut -c8 ` != "-" ]; then
            echo "Other Read permission set on directory $dir" >> $AUDITDIR/home_permission_$TIME.log

        fi

        if [ `echo $dirperm | /bin/cut -c9 ` != "-" ]; then
            echo "Other Write permission set on directory $dir" >> $AUDITDIR/home_permission_$TIME.log
        fi
        if [ `echo $dirperm | /bin/cut -c10 ` != "-" ]; then
            echo "Other Execute permission set on directory $dir" >> $AUDITDIR/home_permission_$TIME.log
        fi
done

# CIS 6.2.10 – Fichiers dot du home (ne pas être world/group‑writable)
echo "Checking User Dot File Permissions..."
for dir in `/bin/cat /etc/passwd | /bin/egrep -v '(root|sync|halt|shutdown)' |
/bin/awk -F: '($7 != "/sbin/nologin") { print $6 }'`; do
    for file in $dir/.[A-Za-z0-9]*; do

        if [ ! -h "$file" -a -f "$file" ]; then
            fileperm=`/bin/ls -ld $file | /bin/cut -f1 -d" "`

            if [ `echo $fileperm | /bin/cut -c6 ` != "-" ]; then
                echo "Group Write permission set on file $file" >> $AUDITDIR/dotfile_permission_$TIME.log
            fi
            if [ `echo $fileperm | /bin/cut -c9 ` != "-" ]; then
                echo "Other Write permission set on file $file" >> $AUDITDIR/dotfile_permission_$TIME.log
            fi
        fi

    done

done

# CIS 6.2.11 – Fichiers .netrc non recommandés
echo "Checking Permissions on User .netrc Files..."
for dir in `/bin/cat /etc/passwd | /bin/egrep -v '(root|sync|halt|shutdown)' |\
    /bin/awk -F: '($7 != "/sbin/nologin") { print $6 }'`; do
    for file in $dir/.netrc; do
        if [ ! -h "$file" -a -f "$file" ]; then
            fileperm=`/bin/ls -ld $file | /bin/cut -f1 -d" "`
            if [ `echo $fileperm | /bin/cut -c5 ` != "-" ]
            then
                echo "Group Read set on $file" >> $AUDITDIR/netrd_permission_$TIME.log
            fi
            if [ `echo $fileperm | /bin/cut -c6 ` != "-" ]
            then
                echo "Group Write set on $file" >> $AUDITDIR/netrd_permission_$TIME.log
            fi
            if [ `echo $fileperm | /bin/cut -c7 ` != "-" ]
            then
                echo "Group Execute set on $file" >> $AUDITDIR/netrd_permission_$TIME.log
            fi
            if [ `echo $fileperm | /bin/cut -c8 ` != "-" ]
            then
                echo "Other Read  set on $file" >> $AUDITDIR/netrd_permission_$TIME.log
            fi
            if [ `echo $fileperm | /bin/cut -c9 ` != "-" ]
            then
                echo "Other Write set on $file" >> $AUDITDIR/netrd_permission_$TIME.log
            fi
            if [ `echo $fileperm | /bin/cut -c10 ` != "-" ]
            then
                echo "Other Execute set on $file" >> $AUDITDIR/netrd_permission_$TIME.log
            fi
        fi
    done
done

# CIS 6.2.12 – Absence de fichiers .rhosts (obsolètes)
echo "Checking for Presence of User .rhosts Files..."
for dir in `/bin/cat /etc/passwd | /bin/egrep -v '(root|halt|sync|shutdown)' |\
    /bin/awk -F: '($7 != "/sbin/nologin") { print $6 }'`; do
    for file in $dir/.rhosts; do
        if [ ! -h "$file" -a -f "$file" ]; then
            echo ".rhosts file in $dir" >> $AUDITDIR/rhosts_$TIME.log
        fi    done
done

# CIS 6.2.2/6.2.3 – Groupes cohérents entre /etc/passwd et /etc/group
echo "Checking Groups in /etc/passwd..."

for i in $(cut -s -d: -f4 /etc/passwd | sort -u ); do
  grep -q -P "^.*?:x:$i:" /etc/group
  if [ $? -ne 0 ]; then
    echo "Group $i is referenced by /etc/passwd but does not exist in /etc/group" >> $AUDITDIR/audit_$TIME.log
  fi
done

# CIS 6.2.6/6.2.7 – Chaque utilisateur non système possède un home directory existant et correct
echo "Checking That Users Are Assigned Home Directories..."

cat /etc/passwd | awk -F: '{ print $1 " " $3 " " $6 }' | while read user uid dir; do
  if [ $uid -ge 500 -a ! -d "$dir" -a $user != "nfsnobody" ]; then
 echo "The home directory ($dir) of user $user does not exist." >> $AUDITDIR/audit_$TIME.log
 fi
done

# CIS 6.2.8 – Le home directory appartient bien à l'utilisateur
echo "Checking That Defined Home Directories Exist..."

cat /etc/passwd | awk -F: '{ print $1 " " $3 " " $6 }' | while read user uid dir; do
 if [ $uid -ge 500 -a -d "$dir" -a $user != "nfsnobody" ]; then
 owner=$(stat -L -c "%U" "$dir")
 if [ "$owner" != "$user" ]; then
 echo "The home directory ($dir) of user $user is owned by $owner." >> $AUDITDIR/audit_$TIME.log
 fi
 fi
done

# CIS 6.2.17 – UIDs en double
echo "Checking for Duplicate UIDs..."

/bin/cat /etc/passwd | /bin/cut -f3 -d":" | /bin/sort -n | /usr/bin/uniq -c |\
    while read x ; do
    [ -z "${x}" ] && break
    set - $x
    if [ $1 -gt 1 ]; then
        users=`/bin/gawk -F: '($3 == n) { print $1 }' n=$2 \
            /etc/passwd | /usr/bin/xargs`
        echo "Duplicate UID ($2): ${users}" >> $AUDITDIR/audit_$TIME.log
    fi
done

# CIS 6.2.18 – GIDs en double
echo "Checking for Duplicate GIDs..."

/bin/cat /etc/group | /bin/cut -f3 -d":" | /bin/sort -n | /usr/bin/uniq -c |\
    while read x ; do
    [ -z "${x}" ] && break
    set - $x
    if [ $1 -gt 1 ]; then
        grps=`/bin/gawk -F: '($3 == n) { print $1 }' n=$2 \
            /etc/group | xargs`
        echo "Duplicate GID ($2): ${grps}" >> $AUDITDIR/audit_$TIME.log
    fi
done

# CIS 6.2.19 – Noms d'utilisateurs en double
echo "Checking for Duplicate User Names..."

cat /etc/passwd | cut -f1 -d":" | sort -n | /usr/bin/uniq -c |\
    while read x ; do
    [ -z "${x}" ] && break
    set - $x
    if [ $1 -gt 1 ]; then
        uids=`/bin/gawk -F: '($1 == n) { print $3 }' n=$2 \
            /etc/passwd | xargs`
        echo "Duplicate User Name ($2): ${uids}"  >> $AUDITDIR/audit_$TIME.log
    fi
done

# CIS 6.2.20 – Noms de groupes en double
echo "Checking for Duplicate Group Names..."

cat /etc/group | cut -f1 -d":" | /bin/sort -n | /usr/bin/uniq -c |\
    while read x ; do
    [ -z "${x}" ] && break
    set - $x
    if [ $1 -gt 1 ]; then
        gids=`/bin/gawk -F: '($1 == n) { print $3 }' n=$2 \
            /etc/group | xargs`
        echo "Duplicate Group Name ($2): ${gids}"  >> $AUDITDIR/audit_$TIME.log
    fi
done

# CIS 6.2.11/6.2.12 – Fichiers personnels .netrc/.forward/.rhosts
# (Présence déconseillée; déclencher des alertes)
echo "Checking for Presence of User .netrc Files..."

for dir in `/bin/cat /etc/passwd |\
    /bin/awk -F: '{ print $6 }'`; do
    if [ ! -h "$dir/.netrc" -a -f "$dir/.netrc" ]; then
        echo ".netrc file $dir/.netrc exists"  >> $AUDITDIR/audit_$TIME.log
    fi
done

# CIS 6.2.15 – Fichiers .forward déconseillés
echo "Checking for Presence of User .forward Files..."

for dir in `/bin/cat /etc/passwd |\
    /bin/awk -F: '{ print $6 }'`; do
    if [ ! -h "$dir/.forward" -a -f "$dir/.forward" ]; then
        echo ".forward file $dir/.forward exists"  >> $AUDITDIR/audit_$TIME.log
    fi
done

# CIS 3.1.x / 3.2.x / 3.3.x – Paramètres réseau IPv4/IPv6 durcis (ip_forward, redirects, source_route,
# rp_filter, tcp_syncookies, martians, ICMP, accept_ra/redirects IPv6)
# Impact: ip_forward=0 casse routage/NAT; rp_filter=1 peut gêner multi‑homing; accept_ra=0 casse autoconf IPv6.
echo "Modifying Network Parameters..."
cp /etc/sysctl.conf $AUDITDIR/sysctl.conf_$TIME.bak

cat > /etc/sysctl.d/99-CIS.conf << 'EOF'
net.ipv4.ip_forward=0
net.ipv4.conf.all.send_redirects=0
net.ipv4.conf.default.send_redirects=0
net.ipv4.conf.all.accept_source_route=0
net.ipv4.conf.default.accept_source_route=0
net.ipv4.conf.all.accept_redirects=0
net.ipv4.conf.default.accept_redirects=0
net.ipv4.conf.all.secure_redirects=0
net.ipv4.conf.default.secure_redirects=0
net.ipv4.conf.all.log_martians=1
net.ipv4.conf.default.log_martians=1
net.ipv4.route.flush=1
net.ipv4.icmp_echo_ignore_broadcasts=1
net.ipv4.icmp_ignore_bogus_error_responses=1
net.ipv4.icmp_echo_ignore_broadcasts=1
net.ipv4.conf.all.rp_filter=1
net.ipv4.conf.default.rp_filter=1
net.ipv4.tcp_syncookies=1
net.ipv6.conf.all.accept_ra=0
net.ipv6.conf.default.accept_ra=0
net.ipv6.conf.all.accept_redirects=0
net.ipv6.conf.default.accept_redirects=0
net.ipv6.conf.all.disable_ipv6=1
fs.suid_dumpable=0
EOF

# CIS 3.3.x (si IPv6 non requis) – Désactiver IPv6 via sysconfig et modprobe
# Impact: désactive IPv6 globalement → applications/services IPv6‑only ou dual‑stack impactés.
echo "Disabling IPv6..."
cp /etc/sysconfig/network $AUDITDIR/network_$TIME.bak
for i in "NETWORKING_IPV6=no" "IPV6INIT=no"; do
  [[ `egrep -q "^$i" /etc/sysconfig/network` ]] || echo "$i" >> /etc/sysconfig/network
done
[ -f /etc/modprobe.d/ipv6.conf ] && `egrep -q "options ipv6 disable=1" /etc/modprobe.d/ipv6.conf` || echo "options ipv6 disable=1" >> /etc/modprobe.d/ipv6.conf

# CIS 3.1.1 – Désactiver les interfaces sans fil si non utilisées
echo "Disabling WLAN interfaces..."
# Impact: coupe le Wi‑Fi (ok pour serveurs; critique sur postes/portables).
nmcli radio all off

# CIS 5.3.2 – Verrouillage après échecs d'authent (faillock) via authselect
# Impact: risque de verrouillage suite à échecs répétés (scans/scripts). Prévoir procédure de déverrouillage.
echo "Enabling faillock feature with authselect..."
authselect select sssd >/dev/null
authselect enable-feature with-faillock >/dev/null
authselect apply-changes >/dev/null

# CIS 1.10/1.11 – Politique cryptographique système: éviter LEGACY; FUTURE recommandé (ou FIPS selon politique)
# Impact: supprime TLS/algos anciens; peut casser compatibilité avec équipements/clients obsolètes.
echo "Set Crypto Policy to FUTURE"
update-crypto-policies --set FUTURE >/dev/null

# CIS 5.3.9 – Restreindre l'accès à 'su' au groupe wheel
# Impact: 'su' restreint au groupe wheel; si aucun admin dans wheel (ou sudo KO), perte d'accès root via su.
echo "Restricting Access to the su Command..."
cp /etc/pam.d/su $AUDITDIR/su_$TIME.bak
pam_su='/etc/pam.d/su'
line_num="$(grep -n "^\#auth[[:space:]]*required[[:space:]]*pam_wheel.so[[:space:]]*use_uid" ${pam_su} | cut -d: -f1)"
sed -i "${line_num} a auth\trequired\tpam_wheel.so use_uid" ${pam_su}

# Opérationnel (non CIS) – S'assurer que root est bien dans wheel pour su restreint
echo "Add root to group wheel..."
gpasswd -a root wheel >/dev/null

echo ""
echo "Successfully Completed"
echo "Please check $AUDITDIR"
