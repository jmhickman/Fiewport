namespace Fiewport

///
/// <summary>
/// Prebuilt attribute request lists for <c>LdapSearchConfig.properties</c>
/// or client-side trimming via <c>Filter.showMany</c>.
/// Attribute names are lowercase to match Fiewport's decoded map keys.
/// </summary>
///
module AttributePresets =

    ///
    /// <summary>
    /// Minimal identity set — enough to name and type an object.
    /// </summary>
    ///
    let terse =
        [| "cn"
           "name"
           "samaccountname"
           "distinguishedname"
           "objectclass"
           "objectcategory" |]


    ///
    /// <summary>
    /// Everyday user, group, OU, and light computer enumeration attributes.
    /// Omits security descriptors and large binary blobs.
    /// </summary>
    ///
    let standard =
        [| "cn"
           "name"
           "samaccountname"
           "distinguishedname"
           "objectclass"
           "objectcategory"
           "description"
           "memberof"
           "member"
           "primarygroupid"
           "admincount"
           "useraccountcontrol"
           "serviceprincipalname"
           "mail"
           "title"
           "department"
           "manager"
           "whencreated"
           "whenchanged"
           "lastlogontimestamp"
           "pwdlastset"
           "accountexpires"
           "operatingsystem"
           "dnshostname"
           "managedby"
           "gplink"
           "ou" |]


    ///
    /// <summary>
    /// Standard set plus rights, trust, delegation, and legacy LAPS attributes.
    /// Still omits certificate blobs.
    /// </summary>
    ///
    let verbose =
        [| "cn"
           "name"
           "samaccountname"
           "distinguishedname"
           "objectclass"
           "objectcategory"
           "description"
           "memberof"
           "member"
           "primarygroupid"
           "admincount"
           "useraccountcontrol"
           "serviceprincipalname"
           "mail"
           "title"
           "department"
           "manager"
           "whencreated"
           "whenchanged"
           "lastlogontimestamp"
           "pwdlastset"
           "accountexpires"
           "operatingsystem"
           "dnshostname"
           "managedby"
           "gplink"
           "ou"
           "objectsid"
           "objectguid"
           "sidhistory"
           "ntsecuritydescriptor"
           "msds-allowedtodelegateto"
           "msds-allowedtoactonbehalfofotheridentity"
           "msds-groupmsamembership"
           "ms-mcs-admpwd"
           "ms-mcs-admpwdexpirationtime"
           "mslaps-password"
           "mslaps-encryptedpassword"
           "mslaps-passwordexpirationtime"
           "mslaps-encryptedpasswordhistory"
           "mslaps-encrypteddsrmpassword"
           "mslaps-encrypteddsrmpasswordhistory"
           "mslaps-currentpasswordversion"
           "msds-managedpasswordinterval"
           "userprincipalname"
           "displayname"
           "givenname"
           "sn"
           "logoncount"
           "badpwdcount"
           "lockouttime"
           "scriptpath"
           "homedirectory"
           "profilepath"
           "userworkstations"
           "msds-userpasswordexpirytimecomputed"
           "msds-supportedencryptiontypes"
           "msds-principalname"
           "serverreferencebl"
           "msdfsr-computerreferencebl"
           "directreports"
           "info"
           "comment"
           "wwwhomepage" |]
