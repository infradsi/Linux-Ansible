# OS Report (RHEL 7/8/9) — Ansible

## Contenu
- `playbook.yml`
- `templates/report.html.j2`
- `templates/report.csv.j2`
- `scripts/convert_csv_to_xlsx.py` (optionnel)
- `reports/` (répertoire de sortie)

## Pré-requis
- Ansible installé sur la machine de contrôle.
- Un inventaire valide (vous avez fourni `/mnt/data/inventaire-ok_ping.yml`).

## Exécution
```bash
ansible-playbook -i /mnt/data/inventaire-ok_ping.yml playbook.yml
```

Les rapports seront produits dans `./reports/os_report.csv` et `./reports/os_report.html`.

### (Optionnel) Générer un fichier Excel
```bash
pip3 install openpyxl
python3 scripts/convert_csv_to_xlsx.py ./reports/os_report.csv ./reports/os_report.xlsx
```

## Champs collectés
- **Distribution** (ex: RedHat, Rocky, Alma, etc.) 
- **Version** (ex: 7.9, 8.10, 9.4)
- **Patchlevel** = la partie mineure de la version (ex: pour 9.4 → 4)
- **Kernel** (ex: 5.14.0-...) 
- **Arch** (ex: x86_64)
- **Uptime** (format `Xd Yh Zm`)

_Généré le 2025-09-17T14:06:27_
