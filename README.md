# iDRAC-SEKM-Scripting

Dell Secure Enterprise Key manager (SEKM) python scripts for iDRAC

## SEKM Overview

The OpenManage SEKM enables you to use an external Key Management Server (KMS) to manage keys that can then be used by
iDRAC to lock and unlock storage devices on a Dell EMC PowerEdge server. iDRAC requests the KMS to create a key for each
storage controller, and then fetches and provides that key to the storage controller on every host boot so that the
storage controller can then unlock the SEDs.

The advantages of using SEKM over PERC Local Key Management (LKM) are:

    In addition to the LKM–supported “Theft of an SED” use case, SEKM protects from a “Theft of a server”
    use case. Because the keys used to lock and unlock the SEDs are not stored on the server, attackers
    cannot access data even if they steal a server

    Centralized key management at the external Key Management Server and eliminates the hassle of
    passphrase management with PERC LKM.

    SEKM supports the industry standard OASIS KMIP protocol thus enabling use of any external third party
    KMIP server.

## Redfish Overview

There are various Out-of-Band (OOB) systems management standards available in the industry today. However, there is no
single standard that can be easily used within emerging programming standards, can be readily implemented within
embedded systems, and can meet the demands of today’s evolving IT solution models. New IT solutions models have placed
new demands on systems management solutions to support expanded scale, higher security, and multi-vendor openness, while
also aligning with modern DevOps tools and processes. Recognizing these needs, Dell EMC and other IT solutions leaders
within the Distributed Management Task Force (DMTF) undertook the creation of a new management interface standard. After
a multi-year effort, the new standard, Redfish v1.0, was announced in July, 2015.

Redfish’s key benefits include:

* Increased simplicity and usability
* Encrypted connections and generally heightened security
* A programmatic interface that can easily be controlled through scripts
* Based on widely-used standards for web APIs and data formats

Redfish has been designed to support the full range of server architectures from monolithic servers to converged
infrastructure and hyper-scale architecture. The Redfish data model, which defines the structure and format of data
representing server status, inventory and available operational functions, is vendor-neutral. Administrators can then
create management automation scripts that can manage any Redfish compliant server. This is crucial for the efficient
operation of a heterogonous server fleet.

Using Redfish also has significant security benefits: unlike legacy management protocols, Redfish utilizes HTTPS
encryption for secure and reliable communication. All Redfish network traffic, including event notifications, can be
sent encrypted across the network.

Redfish provides a highly organized and easily accessible method to interact with a server using scripting tools. The
web interface employed by Redfish is supported by many programming languages, and its tree-like structure makes
information easier to locate. Data returned from a Redfish query can be turned into a searchable dictionary consisting
of key-value-pairs. By looking at the values in the dictionary, it is easy to locate settings and current status of a
Redfish managed system. These settings can then be updated and actions issued to one or multiple systems.

## iDRAC with Lifecycle Controller Overview

The Integrated Dell Remote Access Controller (iDRAC) is designed to enhance the productivity of server administrators
and improve the overall availability of PowerEdge servers. iDRAC alerts administrators to server problems, enabling
remote server management, and reducing the need for an administrator to physically visit the server. iDRAC with
Lifecycle Controller allows administrators to deploy, update, monitor and manage Dell servers from any location without
the use of agents in a one-to-one or one-to-many method. This out-of-band management allows configuration changes and
firmware updates to be managed from Dell EMC, appropriate third-party consoles, and custom scripting directly to iDRAC
with Lifecycle Controller using supported industry-standard API’s. To support the Redfish standard, the iDRAC with
Lifecycle Controller includes support for the iDRAC REST API in addition to support for the IPMI, SNMP, and WS-Man
standard APIs. The iDRAC REST API builds upon the Redfish standard to provide a RESTful interface for Dell EMC value-add
operations including:

* Information on all iDRAC with Lifecycle Controller out-of-band services—web server, SNMP, virtual media, SSH, Telnet,
  IPMI, and KVM
* Expanded storage subsystem reporting covering controllers, enclosures, and drives
* For the PowerEdge FX2 modular server, detailed chassis information covering power supplies, temperatures, and fans
* With the iDRAC Service Module (iSM) installed under the server OS, the API provides detailed inventory and status
  reporting for host network interfaces including such details as IP address, subnet mask, and gateway for the Host OS.

## Learning more about iDRAC and Redfish

For complete information concerning iDRAC with Lifecycle Controller, see the documents
at http://www.dell.com/idracmanuals .

For an overview of the Redfish implementation for iDRAC with Lifecycle Controller, see these Dell EMC white papers:

- [Implementation of the DMTF Redfish API on Dell EMC PowerEdge Servers](http://en.community.dell.com/techcenter/extras/m/white_papers/20442330)
- [RESTful Server Configuration with iDRAC REST API](http://en.community.dell.com/techcenter/extras/m/white_papers/20443207)

For details on the DMTF Redfish standard, visit https://www.dmtf.org/standards/redfish

## iDRAC SEKM Scripting Library

This GitHub library contains example Python scripts that illustrate the usage of the iDRAC REST API with Redfish to
perform the following actions:

Configure and enable end to end SEKM solution using Thales k170v server - enable_sekm_solution_k170v.py:

* Reads required SEKM input values from ini file
* Creates iDRAC user on Thales server and adds user to Key Users group
* Configures and generates CSR on iDRAC, gets signed cert back from Thales server
* Uploads local CA cert and signed cert to iDRAC
* Enables SEKM on iDRAC
* Enables SEKM on controllers
* Steps:
*        1. Generate the template .ini Eg. "python3.7 enable_sekm_solution_k170v.py -g"
*        2. Edit the file, Eg. "vim enable_sekm_solution_k170v_template.ini" and add your values
*        3. Run script Eg. (Linux) "PYTHONUNBUFFERED=1 python3.7 enable_sekm_solution_k170v.py -ip 10.10.10.1 -u idracsuer -p idracpass -c enable_sekm_solution_k170v_template.ini"
*        Note: Script can take up to 2 hours to complete
*

Prerequisites

* PowerEdge 14G/15G servers
* Minimum iDRAC9 FW 4.00.00.00 with SEKM License
* Python 3.x
* Thales Server k170v

## Support

Please note this code is provided as-is and currently not supported by Dell EMC.

## Report problems or provide feedback

If you run into any problems or would like to provide feedback, please open an issue
here https://github.com/dell/iDRAC-SEKM-Scripting/issues 

