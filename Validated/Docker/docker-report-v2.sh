#!/bin/bash

OUTPUT="docker_report.html"
DATE=$(date "+%Y-%m-%d %H:%M:%S")

cat <<EOF > "$OUTPUT"
<!DOCTYPE html>
<html lang="fr">
<head>
    <meta charset="UTF-8">
    <title>Rapport Docker – $DATE</title>
    <style>
        body {
            font-family: 'Segoe UI', sans-serif;
            background-color: #f4f6f8;
            color: #333;
            padding: 20px;
        }
        h1 {
            color: #2c3e50;
        }
        table {
            width: 100%;
            border-collapse: collapse;
            background: white;
            box-shadow: 0 2px 5px rgba(0,0,0,0.1);
        }
        th, td {
            padding: 10px;
            border: 1px solid #ddd;
        }
        th {
            background-color: #2c3e50;
            color: white;
        }
        tr:nth-child(even) {
            background-color: #f9f9f9;
        }
        code {
            background-color: #eef;
            padding: 3px 5px;
            border-radius: 4px;
            font-family: monospace;
        }
        .status-running {
            color: green;
            font-weight: bold;
        }
        .status-exited {
            color: red;
            font-weight: bold;
        }
    </style>
</head>
<body>
<h1>📦 Rapport Docker du $DATE</h1>
<p>Ce rapport liste les conteneurs Docker présents sur le serveur, avec leurs statuts, adresses, commandes utiles et informations de suivi.</p>
<table>
<tr>
    <th>Nom</th>
    <th>État</th>
    <th>Dernier démarrage</th>
    <th>Dernière modification</th>
    <th>Adresse IP</th>
    <th>Ports</th>
    <th>Emplacement</th>
    <th>Propriétaire</th>
    <th>Fichier de log</th>
    <th>Commande Logs</th>
    <th>Stop</th>
    <th>Restart</th>
</tr>
EOF

containers=$(docker ps -a -q)

for container in $containers; do
    name=$(docker inspect --format='{{.Name}}' "$container" | sed 's/\///')
    state=$(docker inspect --format='{{.State.Status}}' "$container")
    started_at=$(docker inspect --format='{{.State.StartedAt}}' "$container")
    finished_at=$(docker inspect --format='{{.State.FinishedAt}}' "$container")
    ip=$(docker inspect --format='{{range .NetworkSettings.Networks}}{{.IPAddress}} {{end}}' "$container")
    ports=$(docker port "$container" | paste -sd "," -)
    mount_dir=$(docker inspect --format='{{range .Mounts}}{{.Source}} {{end}}' "$container")
    log_path=$(docker inspect --format='{{.LogPath}}' "$container")
    pid=$(docker inspect --format='{{.State.Pid}}' "$container")

    if [ "$pid" -gt 0 ]; then
        user=$(ps -o user= -p "$pid")
    else
        user="(inconnu ou arrêté)"
    fi

    log_cmd="docker logs $name"
    stop_cmd="docker stop $name"
    restart_cmd="docker restart $name"

    status_class="status-$state"

    cat <<EOF >> "$OUTPUT"
<tr>
    <td>$name</td>
    <td class="$status_class">$state</td>
    <td>$started_at</td>
    <td>${finished_at:-N/A}</td>
    <td>$ip</td>
    <td>${ports:-N/A}</td>
    <td>${mount_dir:-N/A}</td>
    <td>$user</td>
    <td>${log_path:-N/A}</td>
    <td><code>$log_cmd</code></td>
    <td><code>$stop_cmd</code></td>
    <td><code>$restart_cmd</code></td>
</tr>
EOF
done

cat <<EOF >> "$OUTPUT"
</table>
</body>
</html>
EOF

echo "✅ Rapport HTML généré : $OUTPUT"

