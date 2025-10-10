---
- name: Unused accounts report (per-task become, no global become)
  hosts: bllincdr03
  gather_facts: yes        # pas besoin d'escalade pour ça

  vars:
    script_remote_path: /ansible-tmp/find_unused_accounts_plus.sh
    csv_remote: /tmp/unused_accounts_enriched.csv
    json_remote: /tmp/unused_accounts_enriched.json
    days_threshold: 90
    skip_users: "root,ansible"
    verbose_flag: "-v"

  tasks:
    - name: (Optionnel) Installer les prérequis - RedHat-like
      package:
        name:
          - util-linux      # lastlog
          - shadow-utils    # chage
        state: present
      when: ansible_facts.os_family == "RedHat"
      become: yes

    - name: (Optionnel) Installer les prérequis - Debian-like
      package:
        name:
          - login           # lastlog
          - passwd          # chage
        state: present
      when: ansible_facts.os_family == "Debian"
      become: yes

    - name: Créer le répertoire de travail
      file:
        path: /ansible-tmp
        state: directory
        owner: root
        group: root
        mode: "0750"
      become: yes

    - name: Déployer le script (force LF, 0755)
      copy:
        src: files/find_unused_accounts_plus.sh
        dest: "{{ script_remote_path }}"
        mode: "0755"
        newline_sequence: "\n"
      become: yes

    - name: Valider la syntaxe du script
      shell: "bash -n {{ script_remote_path }}"
      changed_when: false
      become: yes

    - name: Exécuter le script (accès /etc/shadow requis)
      command:
        argv:
          - "{{ script_remote_path }}"
          - -d
          - "{{ days_threshold | string }}"
          - -o
          - "{{ csv_remote }}"
          - --json
          - "{{ json_remote }}"
          - -s
          - "{{ skip_users }}"
          - "{{ verbose_flag }}"
      register: run_out
      become: yes

    - name: Afficher le résumé d'exécution
      debug:
        var: run_out.stdout_lines
      become: no

    - name: Rendre les rapports lisibles par tous (si tu veux éviter become au fetch)
      file:
        path: "{{ item }}"
        mode: "0644"
      loop:
        - "{{ csv_remote }}"
        - "{{ json_remote }}"
      become: yes

    - name: Rapatrier le CSV
      fetch:
        src: "{{ csv_remote }}"
        dest: "reports/{{ inventory_hostname }}/"
        flat: true
      become: yes

    - name: Rapatrier le JSON
      fetch:
        src: "{{ json_remote }}"
        dest: "reports/{{ inventory_hostname }}/"
        flat: true
      become: yes

    - name: (Optionnel) Nettoyer le script si non nécessaire
      file:
        path: "{{ script_remote_path }}"
        state: absent
      become: yes
