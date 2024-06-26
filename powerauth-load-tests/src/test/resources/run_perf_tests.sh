source /home/azure/.pac_secrets
source .perf_test_config
nohup mvn gatling:test -Dgatling.simulationClass=com.wultra.security.powerauth.test.simulation.PerformanceTestSimulation -Drun.jvmArguments="-Xmx6000m" | tee out_last_test.log