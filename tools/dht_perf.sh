mkdir ro
cd ro
../dht_perf readonly &
cd ..

mkdir ro_nobs
cd ro_nobs
../dht_perf readonly nostrap &
cd ..

mkdir ro_nobs_ping
cd ro_nobs_ping
../dht_perf readonly nostrap ping &
cd ..

mkdir ro_nobs_ping_re30
cd ro_nobs_ping_re30
../dht_perf readonly nostrap ping refresh 30 &
cd ..

mkdir ro_nobs_re30
cd ro_nobs_re30
../dht_perf readonly nostrap refresh 30&
cd ..

mkdir ro_ping
cd ro_ping
../dht_perf readonly ping &
cd ..

mkdir ro_ping_re30
cd ro_ping_re30
../dht_perf readonly ping refresh 30 &
cd ..

mkdir ro_re30
cd ro_re30
../dht_perf readonly refresh 30 &
cd ..





