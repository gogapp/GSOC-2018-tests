# GSOC-2018-tests
This repository contains the test experiments done during GSoC 2018. Please note that this writeup assumes that you already have [dpdk](http://doc.dpdk.org/guides/linux_gsg/index.html) installed on your computer. Also you must be using a linux based OS on your computer(This code has been tested on Ubuntu 16.04LTS).

Clone the github repository
```
git clone https://github.com/gogapp/GSOC-2018-tests.git
cd ~/GSOC-2018-tests/
```
Install the following dependencies:
```
sudo apt-get update
sudo apt-get install libpcap-dev
```
The test experiment uses packet traces requested from Caida for testing of the implemeted algorithms. To process the packet traces libpcap has been used.<br>
To make the code run, you must bind the network adapters to DPDK. In order to check which network adaptes are avaiable run:
```
cd ${RTE_SDK}
sudo ./usertools/dpdk-devbind.py --status
```
Suppose that you have 1 network adapter available to bind to dpdk with ```iface=enp0s8```. Run the following code to bind the network adapter to dpdk:
```
cd ${RTE_SDK}
sudo ifconfig enp0s8 down
sudo ./usertools/dpdk-devbind.py --bind=uio_pci_generic enp0s8
```
## Testing Space Saving Algorithm
Run the following code to build the test and to run it.
```
cd ~/GSOC-2018-tests/space_saving/
make
sudo ./build/blackholing -c 0x3 -n 2
```
## Testing RHHH Algorithm
Run the following code to build the test and to run it.
```
cd ~/GSOC-2018-tests/RHHH/
make
sudo ./build/blackholing -c 0x3 -n 2
```
