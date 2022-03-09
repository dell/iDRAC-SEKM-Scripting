# iDRAC-SEKM-Scripting

Dell Secure Enterprise Key Manager (SEKM) python scripts for configuring complete iDRAC SEKM solution. 

## SEKM (Secure Enterprise Key Manager) Overview

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

For more information:
https://dl.dell.com/content/manual6772278-openmanage-secure-enterprise-key-manager-on-poweredge-servers.pdf

## iLKM (iDRAC Local Key Management) Overview
"iDRAC Local Key Management is a solution for users who do not have plans for Secure Enterprise Key Management (SEKM) 
currently but would like to secure devices using iDRAC and migrate to SEKM at a later point in time. In this solution, 
iDRAC will act as a key manager and generate authentication keys that can then be used to secure supported storage devices. 
Once users decide to move to SEKM they can then migrate from iDRAC based LKM to iDRAC based SEKM solution.

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
enable the iLKM and SEKM storage security solutions

IdracStorageSecurityManagement.py - Script to enable storage security solutions for iLKM on iDRAC and SEKM on PERC|HBA:

Overview of running this script for the first time:
1. Choose one of the solutions to enable PERC SEKM, HBA SEKM, iDRAC SEKM, iLKM, or perform iLKM to iDRAC SEKM transition
2. For solutions PERC SEKM, HBA SEKM, or iDRAC SEKM: Generate the template ini Eg. "python3.7 IdracStorageSecurityManagement.py -g"
   1. Edit this template .ini and fill in the appropriate values for your environment
3. For solutions HBA SEKM, iDRAC SEKM, or iLKM: Decide whether to have physical disks automatically secured or not when enabling solution
   1. Script will set the AutoSecure attribute on the iDRAC
   2. When solution is enabled, the physical disks that support encryption will automatically get secured if AutoSecure is enabled
4. For iLKM and iLKM to SEKM transition solutions: Choose a key id and key passphrase to create the security key with

Examples:
Print detailed usage info:
*     python3.7 IdracStorageSecurityManagement.py -h

Generate a template config ini:
*     python3.7 IdracStorageSecurityManagement.py -g

Enable PERC SEKM solution with Thales k170v:
*     python3.7 IdracStorageSecurityManagement.py -ip <idrac ip> -u <idrac user> -p <idrac pass> --perc-sekm -c <filename>.ini

Enable HBA SEKM solution with Thales k170v: 
*     python3.7 IdracStorageSecurityManagement.py -ip <idrac ip> -u <idrac user> -p <idrac pass> --hba-sekm -c <filename>.ini

Enable iDRAC SEKM solution: 
*     python3.7 IdracStorageSecurityManagement.py -ip <idrac ip> -u <idrac user> -p <idrac pass> --idrac-sekm -c <filename>.ini

Enable iLKM solution: 
*     python3.7 IdracStorageSecurityManagement.py -ip <idrac ip> -u <idrac user> -p <idrac pass> --ilkm --ilkm-key-id <key id> --ilkm-key-passphrase <key passphrase>

Transition iLKM to SEKM solution: 
*     python3.7 IdracStorageSecurityManagement.py --ilkm-to-sekm --enable-autosecure -ip <idrac ip> -u <idrac user> -p <idrac pass> -c <filename>.ini --ilkm-key-id <key id> --ilkm-key-passphrase <key passphrase>

* PowerEdge 14G/15G servers
* Minimum iDRAC9 FW 4.00.00.00 with SEKM License
* Python 3.x
* Thales Server k170v (Not required for iLKM)

## Support

Please note this code is provided as-is and currently not supported by Dell EMC.

## Report problems or provide feedback

If you run into any problems or would like to provide feedback, please open an issue
here https://github.com/dell/iDRAC-SEKM-Scripting/issues 

