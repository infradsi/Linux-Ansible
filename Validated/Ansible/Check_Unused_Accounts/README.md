# Unused Accounts Audit (Enhanced) — with Consolidation

Scripts et playbook Ansible pour auditer l'inactivité des comptes UNIX/Linux, produire des rapports par hôte **CSV/JSON** et une **consolidation multi-hôtes** (CSV + HTML).

## Contenu
- `find_unused_accounts_plus.sh` : script Bash autonome.
- `tools/consolidate_unused_accounts.py` : consolide tous les CSV rapatriés en un CSV+HTML.
- `ansible/` :
  - `inventory.ini` : inventaire d'exemple.
  - `group_vars/all.yml` : variables par défaut (seuil, exclusions, sorties).
  - `playbook_unused_accounts.yml` : déploiement, exécution, rapatriement, **consolidation**.

## Utilisation rapide (local)
```bash
sudo bash find_unused_accounts_plus.sh -d 90 -o ./unused_accounts_enriched.csv --json ./unused_accounts_enriched.json -s "root,ansible" -v
```

## Via Ansible (multi-hôtes + consolidation)
```bash
cd ansible
ansible-playbook -i inventory.ini playbook_unused_accounts.yml -b
```
- Rapports individuels : `ansible/reports/<hostname>/unused_accounts_enriched.csv`
- Consolidation : `ansible/reports/_consolidated/consolidated_unused_accounts.csv` et `.html`

## Champs CSV
`user,uid,gid,threshold_days,days_since_last_activity,last_login,last_password_change,activity_source,status,account_state,shell,home`  
La consolidation ajoute une colonne `host` en première position.

## Notes
- Par défaut, seuls les shells listés dans `/etc/shells` sont considérés comme interactifs (`-i` pour inclure les non-interactifs).
- Dépendances côté cible : `lastlog`, `chage`, `awk`, `date`.
- La consolidation tourne côté **contrôleur** (Python 3).
