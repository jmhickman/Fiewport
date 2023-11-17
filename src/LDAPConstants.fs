namespace Fiewport

module LDAPConstants =
    
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





        