source /home/azure/.pac_secrets
source /home/azure/perf-tests/.perf_test_config
nohup mvn gatling:test -Dgatling.simulationClass=com.wultra.security.powerauth.test.simulation.PerformanceTestSimulation -Drun.jvmArguments="-Xmx6000m" > out_last_test.txt 2>&1