require 'rubygems'
require 'nokogiri'

include Nokogiri

Puppet::Type.type(:ad_acl).provide(:default) do
  mk_resource_methods

  # windows only
  confine kernel: :windows

  # powershell, powershell, powershell.  where to find it.
  commands ps:     if File.exist?("#{ENV['SYSTEMROOT']}\\sysnative\\WindowsPowershell\\v1.0\\powershell.exe")
                     "#{ENV['SYSTEMROOT']}\\sysnative\\WindowsPowershell\\v1.0\\powershell.exe"
                   elsif File.exist?("#{ENV['SYSTEMROOT']}\\system32\\WindowsPowershell\\v1.0\\powershell.exe")
                     "#{ENV['SYSTEMROOT']}\\system32\\WindowsPowershell\\v1.0\\powershell.exe"
                   else
                     'powershell.exe'
                   end

  def initialize(value = {})
    super(value)
    @property_flush = {}
  end

  def access_rules=(value)
    @property_flush[:access_rules] = value
  end

  def audit_rules=(value)
    @property_flush[:audit_rules] = value
  end

  def set_access_rule(access_rule)
    # puts audit_rule
    ad_rights = access_rule['ad_rights'].to_s.split(%r{,\s*})

    ad_build = ''

    ad_rights.each do |ad_right|
      ad_build << "$ActiveDirectoryRightsArray += [System.DirectoryServices.ActiveDirectoryRights]::#{ad_right}\n"
    end

    <<~HEREDOC

$ActiveDirectoryRightsArray = @()

#{ad_build}

$objUser = New-Object System.Security.Principal.NTAccount('#{audit_rule['identity']}')

$objSid = $objUser.Translate([System.Security.Principal.SecurityIdentifier])

$AccessRule = New-Object System.DirectoryServices.ActiveDirectoryAuditRule($objSid,
  $ActiveDirectoryRightsArray,
  [System.Security.AccessControl.AccessControlType]::$AccessControlType,
  $objectGuidObj,
  [System.DirectoryServices.ActiveDirectorySecurityInheritance]::$ActiveDirectorySecurityInheritance,
  $inheritedObjectGuidObj)

$my_acl.AddAccessRule($AccessRule)
HEREDOC
  end

  def set_audit_rule(audit_rule)
    # puts audit_rule
    ad_rights = audit_rule['ad_rights'].to_s.split(%r{,\s*})

    ad_build = ''

    ad_rights.each do |ad_right|
      ad_build << "$ActiveDirectoryRightsArray += [System.DirectoryServices.ActiveDirectoryRights]::#{ad_right}\n"
    end

    <<~HEREDOC

$ActiveDirectoryRightsArray = @()

#{ad_build}

$objUser = New-Object System.Security.Principal.NTAccount('#{audit_rule['identity']}')

$objSid = $objUser.Translate([System.Security.Principal.SecurityIdentifier])

$AuditRule = New-Object System.DirectoryServices.ActiveDirectoryAuditRule($objSid,
  $ActiveDirectoryRightsArray,
  [System.Security.AccessControl.AuditFlags]::#{audit_rule['audit_flags']},
  [System.DirectoryServices.ActiveDirectorySecurityInheritance]::#{audit_rule['inheritance_type']})

$my_acl.AddAuditRule($AuditRule)
HEREDOC
  end

  def set_rules(rules, rule_type)
    rule_builder = ''

    rules.each do |audit_rule|
      rule_builder << set_audit_rule(audit_rule) if rule_type == 'audit'
      rule_builder << set_access_rule(audit_rule) if rule_type == 'access'
    end

    <<~HEREDOC

Import-Module ActiveDirectory

$ad_object = Get-ADDomain

$my_acl = Get-Acl -Path "Microsoft.ActiveDirectory.Management\\ActiveDirectory:://RootDSE/#{resource[:name]},$ad_object"

#{rule_builder}

Set-Acl -Path "Microsoft.ActiveDirectory.Management\\ActiveDirectory:://RootDSE/#{resource[:name]},$ad_object" -AclObject $my_acl
HEREDOC
  end

  def self.ad_result_query()
    <<~HEREDOC

    Import-Module ActiveDirectory

    $ad_object = Get-ADDomain
    $ad_object_length = $ad_object.DistinguishedName.Length

    $my_acl = Get-ADObject -Filter * -SearchScope 2 -PipelineVariable Obj -SearchBase "CN=System,$ad_object" -Properties "DistinguishedName" | ForEach {
                Get-Acl -Path "Microsoft.ActiveDirectory.Management\\ActiveDirectory:://RootDSE/$Obj" -Audit  -PipelineVariable Acl | ForEach {
                  $audits = @()

                  $Acl.Audit | ForEach {
                    If ($_.ObjectType -eq '00000000-0000-0000-0000-000000000000') {
                      $audits += $_
                    }
                  }

                  $access = @()

                  $Acl.Access | ForEach {
                    If ($_.ObjectType -eq '00000000-0000-0000-0000-000000000000') {
                      $access += $_
                    }
                  }

                  [pscustomobject]@{
                    Path= $Acl.Path.Substring(64, $Acl.Path.Length - ($ad_object_length + 65))
                    Group=$Acl.Group;
                    Owner=$Acl.Owner;
                    Audit = $audits;
                    Access = $access
                  }
                }
              }  | ConvertTo-XML -As String -Depth 2 -NoTypeInformation

              Write-Host $my_acl
HEREDOC
  end

  def set_acl
    if @property_flush[:group]
    end
    if @property_flush[:owner]
    end
    if @property_flush[:access_rules]
      ps(set_rules(@property_flush[:access_rules], 'access'))
    end
    if @property_flush[:audit_rules]
      ps(set_rules(@property_flush[:audit_rules], 'audit'))
    end
  end

  def flush
    set_acl

    # Collect the resources again once they've been changed (that way `puppet
    # resource` will show the correct values after changes have been made).
    @property_hash = self.class.get_acl(resource[:name])
  end

  def self.prefetch(resources)
    instances.each do |provider|
      resource = resources[provider.name]

      resource.provider = provider if resource
    end
  end

  def self.process_acl_xml(result)
    # an array to store feature hashes
    acls = []

    # create the XML document and parse the objects
    doc = Nokogiri::XML(result)

    doc.xpath('/Objects/Object').each do |object|
      name = object.xpath("./Property[@Name='Path']").text.split('/')[-1]
      owner = object.xpath("./Property[@Name='Owner']").text.downcase
      group = object.xpath("./Property[@Name='Group']").text.downcase

      audit_rules = []

      object.xpath("./Property[@Name='Audit']/Property").each do |audit|
        audit_rule = {}

        next if (audit.xpath("./Property[@Name='ActiveDirectoryRights']").text == '') || (audit.xpath("./Property[@Name='IsInherited']").text == 'True')
        audit_rule['ad_rights'] = audit.xpath("./Property[@Name='ActiveDirectoryRights']").text
        audit_rule['identity'] = audit.xpath("./Property[@Name='IdentityReference']").text
        audit_rule['audit_flags'] = audit.xpath("./Property[@Name='AuditFlags']").text
        audit_rule['inheritance_type'] = audit.xpath("./Property[@Name='InheritanceType']").text
        audit_rule['object_type'] = audit.xpath("./Property[@Name='ObjectType']").text
        audit_rule['inherited_object_type'] = audit.xpath("./Property[@Name='InheritedObjectType']").text

        audit_rules << audit_rule
      end

      access_rules = []

      object.xpath("./Property[@Name='Access']/Property").each do |access|
        access_rule = {}

        next if (access.xpath("./Property[@Name='ActiveDirectoryRights']").text == '') || (access.xpath("./Property[@Name='IsInherited']").text == 'True')
        access_rule['identity'] = access.xpath("./Property[@Name='IdentityReference']").text
        access_rule['ad_rights'] = access.xpath("./Property[@Name='ActiveDirectoryRights']").text
        access_rule['access_control_type'] = access.xpath("./Property[@Name='AccessControlType']").text
        access_rule['object_type'] = access.xpath("./Property[@Name='ObjectType']").text
        access_rule['inheritance_type'] = access.xpath("./Property[@Name='InheritanceType']").text
        access_rule['inherited_object_type'] = access.xpath("./Property[@Name='InheritedObjectType']").text

        access_rules << access_rule
      end

      # put name and state into a hash
      acl_hash = {
        name: name.downcase,
        owner: owner,
        group: group,
        access_rules: access_rules,
        audit_rules: audit_rules
      }

      # push hash to feature array
      acls.push(acl_hash)
    end

    acls
  end

  def self.get_acl(name)
    result = ps("Import-Module ActiveDirectory; $ad_object = Get-ADDomain; Get-Acl -Path 'Microsoft.ActiveDirectory.Management\\ActiveDirectory:://RootDSE/#{name},$ad_object' -Audit | ConvertTo-XML -As String -Depth 2 -NoTypeInformation")

    process_acl_xml(result)[0]
  end

  def self.instances
    query = ad_result_query()
    result = ps(query)

    acls = process_acl_xml(result)

    # map the feature array
    acls.map do |acl|
      new(acl)
    end
  end
end