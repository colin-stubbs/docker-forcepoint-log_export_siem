# docker-forcepoint-log_export_siem

Containerised version of the Forcepoint Log Export SIEM tool

# build

Expressed as shell,

```
CONTAINER_ORG="yourorg"
CONTAINER_NAME="forcepoint-log_export_siem"
CONTAINER_TAG="latest"

# optional
# docker rmi --force "${CONTAINER_ORG}/${CONTAINER_NAME}"

docker build --rm=true --force-rm=true --no-cache -t "${CONTAINER_ORG}/${CONTAINER_NAME}:${CONTAINER_TAG}" -f ./Dockerfile .
```

Example build,

```
user@host docker-forcepoint-log_export_siem % CONTAINER_ORG="routedlogic"
user@host docker-forcepoint-log_export_siem % CONTAINER_NAME="forcepoint-log_export_siem"
user@host docker-forcepoint-log_export_siem % CONTAINER_TAG="latest"
user@host docker-forcepoint-log_export_siem % docker build --rm=true --force-rm=true --no-cache -t "${CONTAINER_ORG}/${CONTAINER_NAME}:${CONTAINER_TAG}" -f ./Dockerfile .
[+] Building 44.3s (9/9) FINISHED                                                                                                                          
 => [internal] load build definition from Dockerfile                                                                                                  0.0s
 => => transferring dockerfile: 743B                                                                                                                  0.0s
 => [internal] load .dockerignore                                                                                                                     0.0s
 => => transferring context: 2B                                                                                                                       0.0s
 => [internal] load metadata for quay.io/centos/centos:stream8                                                                                        1.2s
 => CACHED [1/4] FROM quay.io/centos/centos:stream8@sha256:c9acf46f90fcb637eff59e269fbbebf5ec9e6b6215a07fbe2bbad7429aad6e7e                           0.0s
 => [internal] load build context                                                                                                                     0.0s
 => => transferring context: 223B                                                                                                                     0.0s
 => [2/4] COPY docker-entrypoint.sh /usr/local/bin/docker-entrypoint                                                                                  0.0s
 => [3/4] COPY forcepoint/ /home/forcepoint                                                                                                           0.0s
 => [4/4] RUN adduser -u 1000 -m forcepoint &&   chown -Rv forcepoint:forcepoint /home/forcepoint &&   chmod 0644 /home/forcepoint/*.* &&   dnf -y   42.6s
 => exporting to image                                                                                                                                0.5s
 => => exporting layers                                                                                                                               0.5s
 => => writing image sha256:3bc60dd5c9d941d112d58e5740e449109d3f6ea5853c2cec36107f6835556a55                                                          0.0s
 => => naming to docker.io/routedlogic/forcepoint-log_export_siem:latest                                                                              0.0s

Use 'docker scan' to run Snyk tests against images to find vulnerabilities and learn how to fix them                                                       
user@host docker-forcepoint-log_export_siem %
```

You'll now have a container to run, container output will indicate if the username/password/etc is working or not.

```
user@host docker-forcepoint-log_export_siem % docker image ls | grep -e ^REP -e forcepoint
REPOSITORY                                               TAG       IMAGE ID       CREATED          SIZE
routedlogic/forcepoint-log_export_siem                   latest    3bc60dd5c9d9   56 seconds ago   547MB
user@host docker-forcepoint-log_export_siem %
```

Standard output from the container will give you and idea of what's happening, including if authentication to the Forcepoint API is failing.

You will need to pass the FORCEPOINT_USERNAME and FORCEPOINT_PASSWORD values at minimum, as the defaults will simply be "CHANGE_ME"

The FORCEPOINT_HOST is optional; if Forcepoint tells you to utilise another value for the API host override the default using this as an environment variable.

```
user@host docker-forcepoint-log_export_siem % docker run --env FORCEPOINT_USERNAME=different_value --env FORCEPOINT_PASSWORD=different_password routedlogic/forcepoint-log_export_siem
Fri Jan 13 03:55:40 UTC 2023: Starting Forcepoint Log Export to SIEM container
FORCEPOINT_USERNAME='different_value'
FORCEPOINT_PASSWORD is set
Arguments:
service_username = different_value
service_host = sync-web.mailcontrol.com
max_download_children = 1
infinite_loop =
verbose = 1
proxy =
do_md5sum =
list_only =
dest_dir = /home/forcepoint/logs
opt_stream = all
pid_file = /home/forcepoint/ftl.pid
cfg_file = /home/forcepoint/log_export_siem.cfg
max_batch_size = 0



Opening pid file: /home/forcepoint/log_export_siem.cfg.pid
Trying to Lock: /home/forcepoint/log_export_siem.cfg.pid
Pid file /home/forcepoint/log_export_siem.cfg.pid Locked OK
Opening pid file: /home/forcepoint/ftl.pid
Trying to Lock: /home/forcepoint/ftl.pid
Pid file /home/forcepoint/ftl.pid Locked OK
Downloading filelist from sync-web.mailcontrol.com as different_value
Starting files download
Could not download filelist: 401 Authorization Required
End of process

real    1m5.994s
user    0m0.182s
sys     0m0.037s
Fri Jan 13 03:56:46 UTC 2023: Sleeping for 60 seconds
```
