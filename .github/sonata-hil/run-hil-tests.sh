#!/usr/bin/env bash
set -e

source /opt/labgrid-env/bin/activate

declare -A EXPECTED_STRINGS
EXPECTED_STRINGS["01.SNTP"]="Current UNIX epoch time:"
EXPECTED_STRINGS["02.HTTP"]='<a href="https://iana.org/domains/example">Learn more</a>'
EXPECTED_STRINGS["03.HTTPS"]="No content length header found"
EXPECTED_STRINGS["04.MQTT"]="Done testing MQTT."
EXPECTED_STRINGS["05.HTTP_SERVER"]="Listening on port"

TESTS=("01.SNTP" "02.HTTP" "03.HTTPS" "04.MQTT" "05.HTTP_SERVER")

declare -A RESULTS
overall_result=0

for TEST in "${TESTS[@]}"; do
  EXPECTED="${EXPECTED_STRINGS[$TEST]}"
  echo "--- Flashing $TEST firmware ---"
  cp $(find firmware/$TEST -name "firmware.uf2") "$MOUNT_POINT/"
  sync
  sleep 5
  echo "--- Resetting board ---"
  sudo usbrelay HURTM_1=1
  echo "--- Running $TEST test (timeout: 60s, expecting: '$EXPECTED') ---"
  set +e
  EXPECTED_STRING="$EXPECTED" TEST_TIMEOUT=60 sudo -E `which pytest` --lg-env .github/sonata-hil/local.yaml --no-header -q --tb=no --lg-log /tmp/labgrid-log .github/sonata-hil/test_generic.py
  RESULT=$?
  set -e
  echo "--- $TEST test result: $( [ $RESULT -eq 0 ] && echo PASSED || echo FAILED ) ---"
  echo "--- Serial output ---"
  sudo find /tmp/labgrid-log -type f -exec cat {} \; || true
  sudo rm -rf /tmp/labgrid-log
  echo "--- Cleaning up ---"
  rm -f "$MOUNT_POINT"/*.uf2
  # Board MAC can change for different tests so wipe the dhcp lease table after each test
  sudo systemctl stop dnsmasq
  sudo rm -f /var/lib/misc/dnsmasq.leases
  sudo systemctl start dnsmasq
  RESULTS[$TEST]=$( [ $RESULT -eq 0 ] && echo "passed" || echo "failed" )
  [ $RESULT -ne 0 ] && overall_result=1
done

echo "--- Test summary ---"
for TEST in "${TESTS[@]}"; do
  echo "  $TEST: ${RESULTS[$TEST]}"
done

if [[ $overall_result -ne 0 ]]; then
  echo "One or more hardware tests failed."
  exit 1
else
  echo "All hardware tests passed."
fi
