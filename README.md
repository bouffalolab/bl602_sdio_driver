# bl602_sdio_driver

## BUILD

Goto source code directory and `make [clean]`. The driver bl_fdrv.ko can be found in fullmac directory. The driver code supports Linux kernel from 3.10 to 5.5.19.

## INSTALL

a) Copy firmware wholeimg_if.bin and bl_caldata.bin to /lib/firmware/  

```
Or convert the fw binary and bl_caldata binary to array and put into driver folder  
  1. xxd -i wholeimg_if.bin > bl_fwbin.c xxd -i bl_caldata.bin > bl_caldata.c  
  2. copy the bl_fwbin.c and bl_caldata.c to driver source code  
  3. modify the Makefile vim fullmac/Makefile, turn off the fw bin download CONFIG_BL_DNLD_FWBIN ?=n  
```

b) Install WLAN driver insmod bl_fdrv.ko  
c) Uninstall driver ifconfig wlan0 down rmmod bl_fdrv
