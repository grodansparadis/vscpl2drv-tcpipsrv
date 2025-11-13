## Install the driver on Linux
You can install the driver using the debian package with

> sudo apt install ./vscpl2drv-websocksrv.y.z.deb

the driver will be installed to /var/lib/vscp/drivers/level2

If you want to use the driver with the [VSCP Daemon](https://grodansparadis.github.io/vscp-doc-spec/#/./vscp_daemon) you need to add it to the vscpd.json file (/etc/vscp/vscpd.json). Se [this document](https://grodansparadis.github.io/vscp/#/configuring_the_vscp_daemon) on how to do this.

For [VSCP Works](https://grodansparadis.github.io/vscp-doc-spec/#/./vscp_works) you need to add the driver in the VSCP Works configuration dialog [Add connection](https://grodansparadis.github.io/vscp-works-qt/#/connections).

For other applications check the documentation for that application on how to add VSCP level II drivers.

You also need to set up a configuration file for the driver itself. If you don't need to dynamically edit the content of this file a good and safe location for it is in the */etc/vscp/* folder alongside the VSCP daemon configuration file.

If you need to do dynamic configuration a good place to put the file is in the */var/vscp/lib/vscp/vscpd/* folder or maybe a subfolder here. Make sure the _vscp_ user can read/write the location.

A sample configuration file is make available in */usr/share/vscpl2drv-websocksrv.so* after installation.

## Install the driver on Windows
In the release section of this site you can find binary files for windows that will install the file for you or unpack a binary that you can copy to the location of choice yourself.

## Install the driver on MacOS
t.b.d.

[filename](./bottom-copyright.md ':include')