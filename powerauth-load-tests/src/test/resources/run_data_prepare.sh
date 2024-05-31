source /home/azure/.pac_secrets
source .perf_test_config
mvn gatling:test -Dgatling.simulationClass=com.wultra.security.powerauth.test.simulation.DataPreparationSimulation -Drun.jvmArguments="-Xmx6000m" | tee out_last_data_prepare.log 2>&1