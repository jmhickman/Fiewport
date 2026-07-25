namespace Fiewport

module LDAPConstants =
    open System
    
    let beginningOfEpoch = DateTime (1601, 1, 1, 0, 0, 0, DateTimeKind.Utc)
    ///
    /// An Enum that doesn't look like one. 
    let uacPropertyFlags =
        [ "SCRIPT";
          "ACCOUNTDISABLE";
          "RESERVED";
          "HOMEDIR_REQUIRED";
          "LOCKOUT";
          "PASSWD_NOTREQD";
          "PASSWD_CANT_CHANGE";
          "ENCRYPTED_TEXT_PWD_ALLOWED";
          "TEMP_DUPLICATE_ACCOUNT";
          "NORMAL_ACCOUNT";
          "RESERVED";
          "INTERDOMAIN_TRUST_ACCOUNT";
          "WORKSTATION_TRUST_ACCOUNT";
          "SERVER_TRUST_ACCOUNT";
          "RESERVED";
          "RESERVED";
          "DONT_EXPIRE_PASSWORD";
          "MNS_LOGON_ACCOUNT";
          "SMARTCARD_REQUIRED";
          "TRUSTED_FOR_DELEGATION";
          "NOT_DELEGATED";
          "USE_DES_KEY_ONLY";
          "DONT_REQ_PREAUTH";
          "PASSWORD_EXPIRED";
          "TRUSTED_TO_AUTH_FOR_DELEGATION";
          "PARTIAL_SECRETS_ACCOUNT" ]


    let msdsSupportedEncryptionTypes =
        [ "RC4_HMAC_MD5"
          "DES_CBC_CRC"
          "DES_CBC_MD5"
          "DES_CBC_CRC, DES_CBC_MD5"
          "RC4"
          "DES_CBC_CRC, RC4"
          "DES_CBC_MD5, RC4"
          "DES_CBC_CRC, DES_CBC_MD5, RC4"
          "AES128"
          "DES_CBC_CRC, AES128"
          "DES_CBC_MD5, AES128"
          "DES_CBC_CRC, DES_CBC_MD5, AES128"
          "RC4, AES128"
          "DES_CBC_CRC, RC4, AES128"
          "DES_CBC_MD5, RC4, AES128"
          "DES_CBC_CBC, DES_CBC_MD5, RC4, AES128"
          "AES256"
          "DES_CBC_CRC, AES256"
          "DES_CBC_MD5, AES256"
          "DES_CBC_CRC, DES_CBC_MD5, AES256"
          "RC4, AES256"
          "DES_CBC_CRC, RC4, AES256"
          "DES_CBC_MD5, RC4, AES256"
          "DES_CBC_CRC, DES_CBC_MD5, RC4, AES256"
          "AES 128, AES256"
          "DES_CBC_CRC, AES128, AES256"
          "DES_CBC_MD5, AES128, AES256"
          "DES_CBC_MD5, DES_CBC_MD5, AES128, AES256"
          "RC4, AES128, AES256"
          "DES_CBC_CRC, RC4, AES128, AES256"
          "DES_CBC_MD5, RC4, AES128, AES256"
          "DES_CBC_CRC, DES_CBC_MD5, RC4-HMAC, AES128-CTS-HMAC-SHA1-96, AES256-CTS-HMAC-SHA1-96" ]
    
    type GroupType =
        | System = 1
        | Global = 2
        | DomainLocal = 4
        | Universal = 8
        | APP_BASIC = 16
        | APP_QUERY =  32
        | SECURITY = -2147483648

    let groupTypeList =
        [ GroupType.System
          GroupType.DomainLocal
          GroupType.Global
          GroupType.Universal
          GroupType.APP_BASIC
          GroupType.APP_QUERY
          GroupType.SECURITY ]


    type SystemFlags =
        | ATTRIBUTE_NOT_REPLICATED = 1
        | ATTRIBUTE_WILL_REPLICATE = 2
        | ATTRIBUTE_IS_CONSTRUCTED = 4
        | CATEGORY_ONE_OBJECT = 16
        | DELETED_IMMEDIATELY = 33554432
        | CANNOT_BE_MOVED = 67108864
        | CANNOT_BE_RENAMED = 134217728
        | OBJECT_MOVABLE_WITH_RESTRICTIONS = 268435456
        | OBJECT_CANNOT_MOVE = 536870912
        | OBJECT_CANNOT_BE_RENAMED = 1073741824
        | CANNOT_BE_DELETED = -2147483648
        
        
    let systemFlagsList =
        [ SystemFlags.ATTRIBUTE_NOT_REPLICATED
          SystemFlags.ATTRIBUTE_WILL_REPLICATE
          SystemFlags.ATTRIBUTE_IS_CONSTRUCTED
          SystemFlags.CATEGORY_ONE_OBJECT
          SystemFlags.DELETED_IMMEDIATELY
          SystemFlags.CANNOT_BE_MOVED
          SystemFlags.CANNOT_BE_RENAMED
          SystemFlags.OBJECT_MOVABLE_WITH_RESTRICTIONS
          SystemFlags.OBJECT_CANNOT_MOVE
          SystemFlags.OBJECT_CANNOT_BE_RENAMED
          SystemFlags.CANNOT_BE_DELETED ]
        
        
    type SAMAccountTypes =
        | SAM_DOMAIN_OBJECT = 0x0
        | SAM_GROUP_OBJECT = 0x10000000
        | SAM_NON_SECURITY_GROUP_OBJECT = 0x10000001
        | SAM_ALIAS_OBJECT = 0x20000000
        | SAM_NON_SECURITY_ALIAS_OBJECT = 0x20000001
        | SAM_USER_OBJECT_OR_NORMAL_ACCOUNT = 0x30000000 // Not sure which of these to use, just combine them
        | SAM_MACHINE_ACCOUNT = 0x30000001
        | SAM_TRUST_ACCOUNT = 0x30000002
        | SAM_APP_BASIC_GROUP = 0x40000000
        | SAM_APP_QUERY_GROUP = 0x40000001
        | SAM_ACCOUNT_TYPE_MAX = 0x7fffffff


    let sAMAccountTypesList =
        [ SAMAccountTypes.SAM_DOMAIN_OBJECT
          SAMAccountTypes.SAM_GROUP_OBJECT
          SAMAccountTypes.SAM_NON_SECURITY_GROUP_OBJECT
          SAMAccountTypes.SAM_ALIAS_OBJECT
          SAMAccountTypes.SAM_NON_SECURITY_ALIAS_OBJECT
          SAMAccountTypes.SAM_USER_OBJECT_OR_NORMAL_ACCOUNT          
          SAMAccountTypes.SAM_MACHINE_ACCOUNT
          SAMAccountTypes.SAM_TRUST_ACCOUNT
          SAMAccountTypes.SAM_APP_BASIC_GROUP
          SAMAccountTypes.SAM_APP_QUERY_GROUP
          SAMAccountTypes.SAM_ACCOUNT_TYPE_MAX ]
    
    
    type ActiveDirectoryRights =
        | AccessSystemSecurity = 16777216
        | CreateChild = 1 
        | Delete = 65536 
        | DeleteChild = 2 
        | DeleteTree = 64 
        | ExtendedRight = 256 
        | GenericAll = 983551 
        | GenericExecute = 131076 
        | GenericRead = 131220 
        | GenericWrite = 131112 
        | ListChildren = 4 
        | ListObject = 128 
        | ReadControl = 1310
        | ReadProperty = 16
        | Self = 8
        | Synchronize = 1048576
        | WriteDacl = 262144
        | WriteOwner = 524288
        | WriteProperty = 32
        
        
    let activeDirectoryRightsList =
        [ ActiveDirectoryRights.AccessSystemSecurity
          ActiveDirectoryRights.CreateChild 
          ActiveDirectoryRights.Delete 
          ActiveDirectoryRights.DeleteChild 
          ActiveDirectoryRights.DeleteTree 
          ActiveDirectoryRights.ExtendedRight 
          ActiveDirectoryRights.GenericAll 
          ActiveDirectoryRights.GenericExecute 
          ActiveDirectoryRights.GenericRead 
          ActiveDirectoryRights.GenericWrite 
          ActiveDirectoryRights.ListChildren 
          ActiveDirectoryRights.ListObject 
          ActiveDirectoryRights.ReadControl
          ActiveDirectoryRights.ReadProperty
          ActiveDirectoryRights.Self
          ActiveDirectoryRights.Synchronize
          ActiveDirectoryRights.WriteDacl
          ActiveDirectoryRights.WriteOwner
          ActiveDirectoryRights.WriteProperty ]
        
        
    type instanceTypes =
        | HeadOfNamingContext = 0x00000001
        | ReplicaNotInstantiated = 0x00000002
        | WritableOnThisDirectory = 0x00000004
        | NamingContextAboveIsHeld = 0x00000008
        | NamingContextBeingConstructed = 0x00000010
        | NamingContextBeingRemoved = 0x00000020


    let instanceTypesList =
        [ instanceTypes.HeadOfNamingContext
          instanceTypes.ReplicaNotInstantiated
          instanceTypes.WritableOnThisDirectory
          instanceTypes.NamingContextAboveIsHeld
          instanceTypes.NamingContextBeingConstructed
          instanceTypes.NamingContextBeingRemoved ]
    
    
    type TrustAttributes =
        | TRUST_ATTRIBUTE_NON_TRANSITIVE = 0x00000001
        | TRUST_ATTRIBUTE_UPLEVEL_ONLY = 0x00000002
        | TRUST_ATTRIBUTE_QUARANTINED_DOMAIN = 0x00000004
        | TRUST_ATTRIBUTE_FOREST_TRANSITIVE = 0x00000008
        | TRUST_ATTRIBUTE_CROSS_ORGANIZATION = 0x00000010
        | TRUST_ATTRIBUTE_WITHIN_FOREST = 0x00000020
        | TRUST_ATTRIBUTE_TREAT_AS_EXTERNAL = 0x00000040
        | TRUST_ATTRIBUTE_USES_RC4_ENCRYPTION = 0x00000080
        | TRUST_ATTRIBUTE_CROSS_ORGANIZATION_NO_TGT_DELEGATION = 0x00000200
        | TRUST_ATTRIBUTE_PIM_TRUST = 0x00000400
        | TRUST_ATTRIBUTE_CROSS_ORGANIZATION_ENABLE_TGT_DELEGATION = 0x00000800
        
        
    let trustAttributesList =
        [ TrustAttributes.TRUST_ATTRIBUTE_NON_TRANSITIVE
          TrustAttributes.TRUST_ATTRIBUTE_UPLEVEL_ONLY
          TrustAttributes.TRUST_ATTRIBUTE_QUARANTINED_DOMAIN
          TrustAttributes.TRUST_ATTRIBUTE_FOREST_TRANSITIVE
          TrustAttributes.TRUST_ATTRIBUTE_CROSS_ORGANIZATION
          TrustAttributes.TRUST_ATTRIBUTE_WITHIN_FOREST
          TrustAttributes.TRUST_ATTRIBUTE_TREAT_AS_EXTERNAL
          TrustAttributes.TRUST_ATTRIBUTE_USES_RC4_ENCRYPTION
          TrustAttributes.TRUST_ATTRIBUTE_CROSS_ORGANIZATION_NO_TGT_DELEGATION
          TrustAttributes.TRUST_ATTRIBUTE_PIM_TRUST
          TrustAttributes.TRUST_ATTRIBUTE_CROSS_ORGANIZATION_ENABLE_TGT_DELEGATION ]


    type TrustDirection =
        | TRUST_DIRECTION_DISABLED = 0x00000000
        | TRUST_DIRECTION_INBOUND = 0x00000001
        | TRUST_DIRECTION_OUTBOUND = 0x00000002
        | TRUST_DIRECTION_BIDIRECTIONAL = 0x00000003


    let trustDirectionList =
        [ TrustDirection.TRUST_DIRECTION_DISABLED
          TrustDirection.TRUST_DIRECTION_INBOUND
          TrustDirection.TRUST_DIRECTION_OUTBOUND
          TrustDirection.TRUST_DIRECTION_BIDIRECTIONAL ]


    type TrustType =
        | TRUST_TYPE_DOWNLEVEL = 0x00000001
        | TRUST_TYPE_UPLEVEL = 0x00000002
        | TRUST_TYPE_MIT = 0x00000003
        | TRUST_TYPE_DCE = 0x00000004


    let trustTypeList =
        [ TrustType.TRUST_TYPE_DOWNLEVEL
          TrustType.TRUST_TYPE_UPLEVEL
          TrustType.TRUST_TYPE_MIT
          TrustType.TRUST_TYPE_DCE ]


    let wellKnownSids =
       Map [ "S-1-0", "Null"
             "S-1-1", "World"
             "S-1-2", "Local"
             "S-1-3-0", "Creator Owner"
             "S-1-3-1", "Creator Group"
             "S-1-3-2", "Creator Owner Server"
             "S-1-5-32-544", "Administrator"
             "S-1-5-32-546", "Guest"
             "S-1-5-32-548", "Account Operators"
             "S-1-5-32-549", "Server Operators"
             "S-1-5-32-550", "Print Operators"
             "S-1-5-32-551", "Backup Operators"
             "S-1-5-32-552", "Replicators"
             "S-1-5-32-554", "Pre-Windows 2000"
             "S-1-5-32-555", "Remote Desktop Users"
             "S-1-5-32-556", "Network Configuration Operators"
             "S-1-5-32-562", "Distributed COM Users"
             "S-1-5-32-578", "Hyper-V Administrators"
             "S-1-5-32-580", "Remote Management Users"
             "S-1-5-32-547", "Power Users"
             "S-1-5-32-545", "Users"
             "S-1-5-11", "Authenticated Users"
             "S-1-5-6", "Service"
             "S-1-5-20", "Network Service"
             "S-1-5-18", "Local System"
             "S-1-5-19", "Local Service"
             "S-1-5-14", "Remote Interactive Logon"
             "S-1-5-10", "Self"
             "S-1-5-9", "Enterprise Domain Controllers"
             "S-1-5-7", "Anonymous Logon"
             "S-1-5-4", "Interactive"
             "S-1-5-3", "Batch"
             "S-1-5-2", "Network" ]


    let networkSids =
        Map [ "500", "Administrator"
              "501", "Guest"
              "502", "krbtgt"
              "512", "Domain Admins"
              "513", "Domain Users"
              "514", "Domain Guests"
              "515", "Domain Computers"
              "516", "Domain Controllers"
              "517", "Cert Publishers"
              "518", "Schema Admins"
              "519", "Enterprise Admins"
              "520", "Group Policy Creator Owners"
              "521", "Read-Only Domain Controllers"
              "522", "Clonable Controllers"
              "525", "Protected Users"
              "526", "Key Admins"
              "527", "Enterprise Key Admins" ]

    // ACE type identifiers
    let accessAllowedAce = 0x00uy
    let accessDeniedAce = 0x01uy
    let accessAllowedObjectAce = 0x05uy
    let accessDeniedObjectAce = 0x06uy
    // Object ACE flags (DWORD at offset+8 in Object ACEs)
    let aceObjectTypePresent = 0x01
    let aceInheritedObjectTypePresent = 0x02

    /// Group Policy Client-Side Extension (CSE) GUIDs.
    /// Source: [MS-GPOD] 1.1.4 and community-curated lists.
    /// Used to resolve gPCMachineExtensionNames / gPCUserExtensionNames attributes.
    let groupPolicyCseGuids =
        Map [
            // Core extensions
            "00000000-0000-0000-0000-000000000000", "Core GPO Engine"
            "827D319E-6EAC-11D2-A4EA-00C04F79F83A", "Security"
            "B1BE8D72-6EAC-11D2-A4EA-00C04F79F83A", "EFS Recovery"
            "803E14A0-B4FB-11D0-A0D0-00A0C90F574B", "Computer Restricted Groups"
            "F3CCC681-B74C-4060-9F26-CD84525DCA2A", "Audit Policy Configuration"
            "16BE69FA-4209-4250-88CB-716CF41954E0", "Central Access Policy Configuration"
            // Scripts
            "40B6664F-4972-11D1-A7CA-0000F87571E3", "Scripts (Startup/Shutdown)"
            "40B66650-4972-11D1-A7CA-0000F87571E3", "Scripts (Logon/Logoff)"
            "42B5FAAE-6536-11D2-AE5A-0000F87571E3", "ProcessScripts"
            // Folder Redirection
            "25537BA6-77A8-11D2-9B6C-0000F8080861", "Folder Redirection"
            "88E729D6-BDC1-11D1-BD2A-00C04FB9603F", "Folder Redirection"
            // Software Installation
            "942A8E4F-A261-11D1-A760-00C04FB9603F", "Software Installation (Computers)"
            "BACF5C8A-A3C7-11D1-A760-00C04FB9603F", "Software Installation (Users)"
            "C6DC5466-785A-11D2-84D0-00C04FB169F7", "Software Installation (appmgmts.dll)"
            // IP Security
            "E437BC1C-AA7D-11D2-A382-00C04F991E27", "IP Security (IPSec)"
            // Internet Explorer
            "A2E30F80-D7DE-11D2-BBDE-00C04F86AE3B", "Internet Explorer Maintenance"
            "FC715823-C5FB-11D1-9EEF-00A0C90347FF", "Internet Explorer Maintenance Extension"
            "4CFB60C1-FAA6-47F1-89AA-0B18730C9FD3", "Internet Explorer Zonemapping"
            "7B849A69-220F-451E-B3FE-2CB811AF94AE", "Internet Explorer User Accelerators"
            "CF7639F3-ABA2-41DB-97F2-81E2C5DBFC5D", "Internet Explorer Machine Accelerators"
            // Certificates
            "53D6AB1B-2488-11D1-A28C-00C04FB94F17", "Certificates"
            // Wireless / Network
            "0ACDD40C-75AC-47AB-BAA0-BF6DE7E7FE63", "Wireless Group Policy"
            "B587E2B1-4D59-4E7E-AED9-22B9DF11D053", "802.3 Group Policy"
            "FB2CA36D-0B40-4307-821B-A13B252DE56C", "Enterprise QoS"
            "426031C0-0B47-4852-B0CA-AC3D37BFCB39", "QoS Packet Scheduler"
            "CDEAFC3D-948D-49DD-AB12-E578BA4AF7AA", "TCPIP"
            // Printers
            "8A28E2C5-8D06-49A4-A08C-632DAA493E17", "Deployed Printer Connections"
            "47BA4403-1AA0-47F6-BDC5-298F96D1C2E3", "Print Policy"
            // Security / VBS
            "F312195E-3D9D-447A-A3F5-08DFFA24735E", "VirtualizationBasedSecurity (DeviceGuard)"
            "D76B9641-3288-4F75-942D-087DE603E3EA", "AdmPwd (LAPS)"
            // Offline Files / Disk Quota
            "C631DF4C-088F-4156-B058-4375F0853CD8", "Microsoft Offline Files"
            "3610EDA5-77EF-11D2-8DC5-00C04FA31A66", "Microsoft Disk Quota"
            // Remote Installation / Desktop
            "3060E8CE-7020-11D2-842D-00C04FA372D4", "Remote Installation Services"
            "4BCD6CDE-777B-48B6-9804-43568E23545D", "Remote Desktop USB Redirection"
            // Work Folders / Search
            "4D968B55-CAC2-4FF5-983F-0A54603781A3", "Work Folders"
            "7933F41E-56F8-41D6-A31C-4148A711EE93", "Windows Search Group Policy"
            // Windows To Go
            "BA649533-0AAC-4E04-B9BC-4DBAE0325B12", "Windows To Go Startup Options"
            "C34B2751-1CF4-44F5-9262-C3FC39666591", "Windows To Go Hibernate Options"
            // ConfigMgr
            "346193F5-F2FD-4DBD-860C-B88843475FD3", "ConfigMgr User State Management"
            // Group Policy Folders / Data Sources
            "6232C319-91AC-4931-9385-E70C2B099F0E", "Group Policy Folders"
            "728EE579-943C-4519-9EF7-AB56765798ED", "Group Policy Data Sources"
            // Application Management
            "C6DC5466-785A-11D2-84D0-00C04FB169F7", "Application Management"
            // Group Policy Applications
            "F9C77450-3A41-477E-9310-9ACD617BD9E3", "Group Policy Applications"
            // Preference CSE items
            "0E28E245-9368-4853-AD84-6DA3BA35BB75", "Preference: Environment Variables"
            "1612B55C-243C-48DD-A449-FFC097B19776", "Preference: Data Sources"
            "17D89FEC-5C44-4972-B12D-241CAEF74509", "Preference: Local Users and Groups"
            "1A6364EB-776B-4120-ADE1-B63A406A76B5", "Preference: Devices"
            "2EA1A81B-48E5-45E9-8BB7-A6E3AC170006", "Preference: Drives"
            "3A0DBA37-F8B2-4356-83DE-3E90BD5C261F", "Preference: Network Options"
            "5794DAFD-BE60-433F-88A2-1A31939AC01F", "Preference: Drives"
            "5C935941-A954-4F7C-B507-885941ECE5C4", "Preference: Internet Settings"
            "6A4C88C6-C502-4F74-8F60-2CB23EDC24E2", "Preference: Network Shares"
            "7150F9BF-48AD-4DA4-A49C-29EF4A8369BA", "Preference: Files"
            "74EE6C03-5363-4554-B161-627540339CAB", "Preference: Ini Files"
            "91FBB303-0CD5-4055-BF42-E512A681B325", "Preference: Services"
            "A3F3E39B-5D83-4940-B954-28315B82F0A8", "Preference: Folder Options"
            "AADCED64-746C-4633-A97C-D61349046527", "Preference: Scheduled Tasks"
            "B087BE9D-ED37-454F-AF9C-04291E351182", "Preference: Registry"
            "BC75B1ED-5833-4858-9BB8-CBF0B166DF9D", "Preference: Printers"
            "C418DD9D-0D14-4EFB-8FBF-CFE535C8FAC7", "Preference: Shortcuts"
            "CF848D48-888D-4F45-B530-6A201E62A605", "Preference: Start Menu"
            "E47248BA-94CC-49C4-BBB5-9EB7F05183D0", "Preference: Internet Settings"
            "E4F48E54-F38D-4884-BFB9-D4D2E5729C18", "Preference: Start Menu"
            "E5094040-C46C-4115-B030-04FB2E545B00", "Preference: Regional Options"
            "E62688F0-25FD-4C90-BFF5-F508B9D2E31F", "Preference: Power Options"
            // Tool Extension GUIDs
            "0F6B957D-509E-11D1-A7CC-0000F87571E3", "Tool Extension (Computer Policy)"
            "0F6B957E-509E-11D1-A7CC-0000F87571E3", "Tool Extension (User Policy)"
            "D02B1F72-3407-48AE-BA88-E8213C6761F1", "Tool Extension (Computer Policy)"
            "D02B1F73-3407-48AE-BA88-E8213C6761F1", "Tool Extension (User Policy)"
            // Run Restrictions
            "35378EAC-683F-11D2-A89A-00C04FBBCFA2", "Registry Settings"
            // CP (gptext.dll)
            "FBF687E6-F063-4D9F-9F4F-FD9A26ACDD5F", "CP (gptext.dll)"
        ]
        