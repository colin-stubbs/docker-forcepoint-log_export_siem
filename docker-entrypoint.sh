#!/bin/bash -e

PREFIX=/home/forcepoint
LOCK=${PREFIX}/.lock
SLEEP_SECS=60

mkdir -p "${PREFIX}/logs/web"
cd "${PREFIX}"

echo "`date`: Starting Forcepoint Log Export to SIEM container"

# we need to escape any instances of / in the variables password to ensure the sed command will not error
ESCAPED_FORCEPOINT_HOST=`echo "${FORCEPOINT_HOST}" | sed -r -e 's#/#\\\/#'`
ESCAPED_FORCEPOINT_USERNAME=`echo "${FORCEPOINT_USERNAME}" | sed -r -e 's#/#\\\/#'`
ESCAPED_FORCEPOINT_PASSWORD=`echo "${FORCEPOINT_PASSWORD}" | sed -r -e 's#/#\\\/#'`

# fix config file for HOST, USERNAME, PASSWORD
test -n "${FORCEPOINT_HOST}" && \
  echo "FORCEPOINT_HOST='${FORCEPOINT_HOST}'" && \
  sed -i "s/^host=.*$/host=${FORCEPOINT_HOST}/" log_export_siem.cfg
test -n "${FORCEPOINT_USERNAME}" && \
  echo "FORCEPOINT_USERNAME='${FORCEPOINT_USERNAME}'" && \
  sed -i "s/^username=.*$/username=${FORCEPOINT_USERNAME}/" log_export_siem.cfg
test -n "${FORCEPOINT_PASSWORD}" && \
  echo "FORCEPOINT_PASSWORD is set" && \
  sed -i "s/^password=.*$/password=${ESCAPED_FORCEPOINT_PASSWORD}/" log_export_siem.cfg

while true ; do
  # Create a new CSV dump file every time we run, we will remove the first line
  # which is the column names so that Elastic Agent doesn't ingest it and
  # generate a garbage log
  CURRENT_LOG="${PREFIX}/logs/web/dump_`date +%Y%m%d%H%M%S`.csv"

  time perl ${PREFIX}/log_export_siem.pl --cfgfile ${PREFIX}/log_export_siem.cfg

  for i in `find "${PREFIX}/logs/web" -type f -name \*.gz` ; do
    gunzip -c ${i} | grep -v -e '^"Date' > ${CURRENT_LOG} && rm -fv ${i}
  done

  # compress recently ingested logs
  find ${PREFIX}/logs/web -type f -name \*.csv -mtime +1 -exec bzip2 -v {} \;

  # cleanup old files after a week
  find ${PREFIX}/logs/web -type f -name \*.csv -mtime +7 -exec rm -fv {} \;
  find ${PREFIX}/logs/web -type f -name \*.gz -mtime +7 -exec rm -fv {} \;
  find ${PREFIX}/logs/web -type f -name \*.bz2 -mtime +7 -exec rm -fv {} \;

  echo "`date`: Sleeping for ${SLEEP_SECS} seconds"

  sleep ${SLEEP_SECS}
done

# EOF
