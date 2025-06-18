#
# Script to update ansible inventory file in YAML, keeping only ping responsive hosts
# V 1.0 - 10/06/2025
#

import subprocess

input_file = "inventaire-test.yml"
output_file = "inventaire-ok_ping.yml"

def ping_host(host):
    try:
        # -c 1 = 1 ping, -W 2 = 2 sec timeout (Linux)
        res = subprocess.run(['ping', '-c', '1', '-W', '2', host],
                             stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        return res.returncode == 0
    except Exception:
        return False

with open(input_file, "r") as f:
    lines = f.readlines()

new_lines = []
in_hosts_block = False
for line in lines:
    stripped = line.strip()
    # On cherche "hosts:" pour activer la détection d’hôtes sur les lignes suivantes
    if stripped.endswith("hosts:"):
        in_hosts_block = True
        new_lines.append(line)
        continue
    # Si une nouvelle section commence, on quitte le bloc hosts
    if in_hosts_block and (stripped == "" or not line.startswith(" " * 8)):
        in_hosts_block = False
    # Si on est dans le bloc hosts (avec indentation de 8 espaces)
    if in_hosts_block and (line.startswith(" " * 8) or line.startswith(" " * 9)) and not stripped.startswith("#"):
        host = stripped.rstrip(":")
        if host:  # Non vide
            if not ping_host(host):
                # On commente la ligne
                new_lines.append(f"# {line.rstrip()}   # Ping NOK !\n")
            else:
                new_lines.append(line)
        else:
            new_lines.append(line)
    else:
        new_lines.append(line)

with open(output_file, "w") as f:
    f.writelines(new_lines)

print(f"Traitement terminé. Voir : {output_file}")
