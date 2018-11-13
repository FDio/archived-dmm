#!/bin/bash -x
hugepagesize=$(cat /proc/meminfo | grep Hugepagesize | awk -F " " {'print$2'})
if [ "$hugepagesize" == "2048" ]; then
    pages=3000
elif [ "$hugepagesize" == "1048576" ]; then
    pages=5
fi
sudo sysctl -w vm.nr_hugepages=$pages
HUGEPAGES=`sysctl -n  vm.nr_hugepages`
echo "Configured hugepages: $HUGEPAGE" 
if [ $HUGEPAGES != $pages ]; then
    echo "Warning: Unable to get $pages hugepages, only got $HUGEPAGES.  Cannot finish."
fi

