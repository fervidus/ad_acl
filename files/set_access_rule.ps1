param(

      [Parameter(Position=0,Mandatory=$true)]
      [System.String]$SecurityIdentifier,

      [Parameter(Position=1,Mandatory=$true)]
      [ValidateSet('Allow','Deny')]
      [System.String]$AccessControlType,

      [Parameter(Position=2,Mandatory=$true)]
      [ValidateSet('All','Children','Descendents','None','SelfAndChildren')]
      [System.String]$ActiveDirectorySecurityInheritance,

      [Parameter(Position=3,Mandatory=$true)]
      [ValidateSet('CreateChild','DeleteChild','ListChildren','Self','ReadProperty','WriteProperty','DeleteTree','ListObject','ExtendedRight','Delete','ReadControl','GenericExecute','GenericWrite','GenericRead','WriteDacl','WriteOwner','GenericAll','Synchronize','AccessSystemSecurity')]
      [System.String[]]$ActiveDirectoryRights,

      [Parameter(Position=4,Mandatory=$true)]
      [System.String]$Path,

      [Parameter(Position=5,Mandatory=$false)]
      [System.String]$ObjectGuid='00000000-0000-0000-0000-000000000000',

      [Parameter(Position=6,Mandatory=$false)]
      [System.String]$InheritedObjectGuid='00000000-0000-0000-0000-000000000000'
  )
Import-Module ActiveDirectory

$my_acl = Get-Acl -Path "Microsoft.ActiveDirectory.Management\ActiveDirectory:://RootDSE/$Path"

$ActiveDirectoryRightsArray = @()

foreach ($i in $ActiveDirectoryRights) {
$ActiveDirectoryRightsArray += [System.DirectoryServices.ActiveDirectoryRights]::$i
}

$objUser = New-Object System.Security.Principal.NTAccount($SecurityIdentifier)

$objSid = $objUser.Translate([System.Security.Principal.SecurityIdentifier])

$objectGuidObj = New-Object System.Guid($ObjectGuid)
$inheritedObjectGuidObj = New-Object System.Guid($InheritedObjectGuid)

$AuditRule = New-Object System.DirectoryServices.ActiveDirectoryAuditRule($objSid,
  $ActiveDirectoryRightsArray,
  [System.Security.AccessControl.AccessControlType]::$AccessControlType,
  $objectGuidObj,
  [System.DirectoryServices.ActiveDirectorySecurityInheritance]::$ActiveDirectorySecurityInheritance,
  $inheritedObjectGuidObj)

$my_acl.AddAuditRule($AuditRule)

Set-Acl -Path "Microsoft.ActiveDirectory.Management\ActiveDirectory:://RootDSE/$Path" -AclObject $my_acl
