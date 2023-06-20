# Firewall Implementation in ONOS:

## Intro:

A generic implementation of firewalling in ONOS and tested with mininet.

1. ALLOW/DENY rules based of specified source and destination and protocol.
2. ALLOW/DENY rules based of specified port of a device and protocol.
3. ALLOW ALL/DENY ALL rule based of only protocol.


## Dependents & Installation:

- Considering you've already installed ONOS, openvswitch, mininet, maven and java.
- Activate Openflow and Reactive forwarding to connect mininet.
- Connect mininet to onos controller(it'll be helpful while testing the app).
- Build the apps separately using maven: `mvn clean install`, or download the oar files directly from the Releases section.
- Install the `firewall-comp` app first, either by uploading to onos interface or directly from commandline like:

```bash
onos-app <IP> reinstall! <path-to-oar-file>
```
- Then install the `firewall-app` app, in the same manner.
- Once both are installed and activated, head over to: `http://ONOS-IP:8181/onos/v1/docs/#/firewall`, to test the application, using the Swagger UI.

## Basic Reference:

- `/rules`: Supports GET request, returns all rules currently set.
- `/add/bysrc`: Supports POST and DELETE requests, add and remove rules, according to method 1.
- `/add/byport`: Supports POST and DELETE requests, add and remove rules, according to method 2.
- `/add/all`: Supports POST and DELETE requests, add and remove rules, according to method 3.
- `/remove/{id}`: Supports DELETE requests, remove rules, according to specified id in the path parameter.



## Usage:

The following fields in the swagger UI to be filled with these values:

- `Action`: Only ALLOW or DENY. (must be in uppercase)
- `SrcMac` & `DstMac`: Specify the actualy MAC Id of hosts inside Mininet without removing colons and without a VLAN ID. Example- 00:00:00:00:00:01.
- `DeviceId`: Must be the accurate device ID as specified in the onos UI.
- `Protocol`: Currently it doesn't support verbose protocol names, so specify only the byte values: 1 for ICMP, 6 for TCP and so on.
- `Port`: The numeric value of the port you want to block, make sure to know which port is connected to which host from a switch.


## Testing with mininet:

- `Test ICMP`: generic pingall will do the work, the results will be reflected as expected.
- `Test TCP`: Suppose TCP blocking rule implemented between h1 and h2, do the following in mininet:

```
mininet>h1 python -m http.server 80 &

```
- Since h2 is blocked, this wont work:
```
mininet>h2 wget -O - h1
```
- But h3 is not blocked, hence this would work:
```
mininet>h3 wget -O - h1
```






