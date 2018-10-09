#################################################
# Considerations:

  1. Considers each file inside the path "dmm/scripts/csit/run/" as a single test case.
  2. Considers all files inside "dmm/scripts/csit/run/" as Test scripts,
     So any helper files can be written in the path "dmm/scripts/csit/"
  3. Considers a test case as SUCCESS only when both the client and server echoes
     DMM_CSIT_TEST_PASSED during verification.

#################################################
# Call stack of each test script from CSIT script:

===============================================================================
./test_script.sh  action  which_node     interface_name      dut1_ip   dut2_ip
===============================================================================
./test_script.sh  setup      0        dut1_to_dut2_if_name   dut1_ip   dut2_ip
./test_script.sh  setup      1        dut2_to_dut1_if_name   dut1_ip   dut2_ip
./test_script.sh  run        0        dut1_to_dut2_if_name   dut1_ip   dut2_ip
./test_script.sh  run        1        dut2_to_dut1_if_name   dut1_ip   dut2_ip
./test_script.sh  verify     0
./test_script.sh  verify     1
./test_script.sh  log        0
./test_script.sh  log        1
./test_script.sh  cleanup    0
./test_script.sh  cleanup    1

[0-dut1, 1-dut2]

#################################################
# Want to write a new Test case ?

  1. make a new script in "dmm/scripts/csit/run/" with the help of
     "dmm/scripts/csit/template.sh".
  2. And handle all the actions in it(can go through existing scripts for reference).