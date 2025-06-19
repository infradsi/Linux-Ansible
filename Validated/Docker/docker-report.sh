# Create a docker report for the current server
# MGH / V1.0 / Test

#!/bin/bash

# Fichier de sortie HTML
OUTPUT="docker_report.html"

# Créer l'en-tête HTML
cat <<EOF > "$OUTPUT"
<!DOCTYPE html>
<html lang="fr">
<head>
    <meta charset="UTF-8">
    <title>Rapport Docker</title>
    <style>
        body { font-family: Arial, sans-serif; }
        table { border-collapse: collapse; width: 100%; }
        th, td { border: 1px solid #ccc; padding: 8px; text-align: left; }
        th { background-color: #f2f2f2; }
        code { background-color: #eee; padding: 2px 4px; font-family: monospace; }
    </style>
</head>
<body>
<h1>Rapport des Conteneurs Docker</h1>
<p>Généré le : $(date)</p>
<table>
<tr>
    <th>Nom</th>
    <th>État</th>
    <th>Dernier démarrage</th>
    <th>Adresse IP</th>
    <th>Ports</th>
    <th>Emplacement</th>
    <th>Propriétaire</th>
    <th>Log path</th>
    <th>Commande pour lire le log</th>
</tr>
EOF

# Obtenir les IDs des conteneurs (tous, même arrêtés)
containers=$(docker ps -a -q)

for container in $containers; do
    name=$(docker inspect --format='{{.Name}}' "$container" | sed 's/\///')
    state=$(docker inspect --format='{{.State.Status}}' "$container")
    started_at=$(docker inspect --format='{{.State.StartedAt}}' "$container")
    ip=$(docker inspect --format='{{range .NetworkSettings.Networks}}{{.IPAddress}} {{end}}' "$container")
    ports=$(docker port "$container" | paste -sd "," -)
    mount_dir=$(docker inspect --format='{{range .Mounts}}{{.Source}} {{end}}' "$container")

    # Utilisateur propriétaire via PID
    pid=$(docker inspect --format='{{.State.Pid}}' "$container")
    if [ "$pid" -gt 0 ]; then
        user=$(ps -o user= -p "$pid")
    else
        user="(inconnu ou arrêté)"
    fi

    # Chemin du log (dépend de la config Docker, par défaut dans /var/lib/docker/containers)
    log_path=$(docker inspect --format='{{.LogPath}}' "$container")

    # Commande pour lire les logs (docker logs ou fichier brut)
    log_cmd="docker logs $name"

    # Ajouter une ligne HTML
    cat <<EOF >> "$OUTPUT"
<tr>
    <td>$name</td>
    <td>$state</td>
    <td>$started_at</td>
    <td>$ip</td>
    <td>${ports:-N/A}</td>
    <td>${mount_dir:-N/A}</td>
    <td>$user</td>
    <td>${log_path:-N/A}</td>
    <td><code>$log_cmd</code></td>
</tr>
EOF
done

# Fermer le HTML
cat <<EOF >> "$OUTPUT"
</table>
</body>
</html>
EOF

echo "Rapport généré : $OUTPUT"

