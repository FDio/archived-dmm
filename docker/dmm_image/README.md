# How to build the image of dmm
Note: Make sure your computer can connect to the network
```sh
    #cd dmm/docker/dmm_image/centos
    #docker build -t "dmm:tag" .
```

# How to use the image of dmm
```sh
	#docker run -i -t --network=host -v /sys/bus/pci/devices:/sys/bus/pci/devices -v /sys/devices/system/node:/sys/devices/system/node -v /mnt/nstackhuge:/mnt/nstackhuge -v /dev:/dev --privileged dmm:tag /bin/bash
```

Then we will enter a container and we can build dmm and run the app.
