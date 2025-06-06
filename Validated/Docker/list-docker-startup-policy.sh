docker container ls -q | xargs docker container inspect --format '{{ .Name }}: {{.HostConfig.RestartPolicy.Name}}'
