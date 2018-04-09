require 'rubygems'
require 'nokogiri'

include Nokogiri

Puppet::Type.type(:ad_acl).provide(:default) do
  Puppet.debug('Jack testing begining of provider')

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
    Puppet.debug('Jack testing initialize')

    super(value)
    @property_flush = {}
  end

  def access_rules=(value)
    Puppet.debug('Jack testing access_rules=(value)')

    @property_flush[:access_rules] = value
  end

  def audit_rules=(value)
    Puppet.debug('Jack testing audit_rules(value)')

    @property_flush[:audit_rules] = value
  end

  def set_access_rule(access_rule)
    Puppet.debug('Jack testing set_access_rule(access_rule)')

    # puts audit_rule
    ad_rights = access_rule['ad_rights'].to_s.split(%r{,\s*})

    ad_build = ''

    ad_rights.each do |ad_right|
      ad_build << "$ActiveDirectoryRightsArray += [System.DirectoryServices.ActiveDirectoryRights]::#{ad_right}\n"
    end

    <<-HEREDOC

      $ActiveDirectoryRightsArray = @()

      #{ad_build}

      $objSid = New-Object System.Security.Principal.SecurityIdentifier('#{access_rule['identity']}')

      $AccessRule = New-Object System.DirectoryServices.ActiveDirectoryAuditRule($objSid,
        $ActiveDirectoryRightsArray,
        [System.Security.AccessControl.AccessControlType]::#{access_rule['access_control_type']},
        $objectGuidObj,
        [System.DirectoryServices.ActiveDirectorySecurityInheritance]::#{access_rule['inheritance_type']},
        $inheritedObjectGuidObj)

      $my_acl.AddAccessRule($AccessRule)
    HEREDOC
  end

  def set_audit_rule(audit_rule)
    Puppet.debug('Jack testing set_audit_rule(audit_rule)')
    Puppet.debug("Jack testing set_audit_rule(audit_rules) audit_rule: #{audit_rule}")

    # puts audit_rule
    ad_rights = audit_rule['ad_rights'].to_s.split(%r{,\s*})

    ad_build = ''

    ad_rights.each do |ad_right|
      ad_build << "$ActiveDirectoryRightsArray += [System.DirectoryServices.ActiveDirectoryRights]::#{ad_right}\n"
    end

    <<-HEREDOC

      $ActiveDirectoryRightsArray = @()

      #{ad_build}

      $objSid = New-Object System.Security.Principal.SecurityIdentifier('#{audit_rule['identity']}')

      $AuditRule = New-Object System.DirectoryServices.ActiveDirectoryAuditRule($objSid,
        $ActiveDirectoryRightsArray,
        [System.Security.AccessControl.AuditFlags]::#{audit_rule['audit_flags']},
        [System.DirectoryServices.ActiveDirectorySecurityInheritance]::#{audit_rule['inheritance_type']})

      $my_acl.AddAuditRule($AuditRule)
    HEREDOC
  end

  def set_rules(rules, rule_type)
    Puppet.debug('Jack testing set_rules')

    rule_builder = ''

    rules.each do |rule|
      rule_builder << set_audit_rule(rule) if rule_type == 'audit'
      rule_builder << set_access_rule(rule) if rule_type == 'access'
    end

    <<-HEREDOC

      Import-Module ActiveDirectory

      $my_acl = Get-Acl -Path "Microsoft.ActiveDirectory.Management\\ActiveDirectory:://RootDSE/#{resource[:name]}"

      #{rule_builder}

      Set-Acl -Path "Microsoft.ActiveDirectory.Management\\ActiveDirectory:://RootDSE/#{resource[:name]}" -AclObject $my_acl
    HEREDOC
  end

  def self.ad_result_query
    Puppet.debug('Jack testing selt.ad_result_query')

    <<-HEREDOC

      Import-Module ActiveDirectory

      $my_acl = Get-ADObject -Filter * -SearchScope 2 -PipelineVariable Obj -Properties "DistinguishedName" | ForEach {
                  Get-Acl -Path "Microsoft.ActiveDirectory.Management\\ActiveDirectory:://RootDSE/$Obj" -Audit  -PipelineVariable Acl | ForEach {
                    $audits = @()

                    $Acl.Audit | ForEach {
                      If ($_.IsInherited -eq $false -And $_.ObjectType -eq '00000000-0000-0000-0000-000000000000' -And $_.InheritedObjectType -eq '00000000-0000-0000-0000-000000000000') {
                        $new_audit = [pscustomobject]@{
                          ActiveDirectoryRights = $_.ActiveDirectoryRights
                          IdentityReference = $_.IdentityReference;
                          AuditFlags = $_.AuditFlags;
                          InheritanceType = $_.InheritanceType;
                          IdentitySID = $_.IdentityReference.Translate([System.Security.Principal.SecurityIdentifier])
                        }

                        $audits += $new_audit
                      }
                    }

                    $access = @()

                    $Acl.Access | ForEach {
                      If ($_.IsInherited -eq $false -And $_.ObjectType -eq '00000000-0000-0000-0000-000000000000' -And $_.InheritedObjectType -eq '00000000-0000-0000-0000-000000000000') {
                        $new_access = [pscustomobject]@{
                          ActiveDirectoryRights = $_.ActiveDirectoryRights
                          IdentityReference = $_.IdentityReference;
                          AccessControlType = $_.AccessControlType;
                          InheritanceType = $_.InheritanceType;
                          IdentitySID = $_.IdentityReference.Translate([System.Security.Principal.SecurityIdentifier])
                        }

                        $access += $new_access
                      }
                    }

                    [pscustomobject]@{
                      Path = $Acl.Path
                      Group = $Acl.Group;
                      Owner = $Acl.Owner;
                      Audit = $audits;
                      Access = $access
                    }
                  }
                }  | ConvertTo-XML -As String -Depth 2

      Write-Host $my_acl
    HEREDOC
  end

  def set_acl
    Puppet.debug('Jack testing set_acl')

    if @property_flush[:group]
      Puppet.debug('Jack testing set_acl property_flush[:group]')

    end
    if @property_flush[:owner]
      Puppet.debug('Jack testing set_acl property_flush[:owner]')

    end
    if @property_flush[:access_rules]
      Puppet.debug('Jack testing set_acl property_flush[:access_rules]')

      ps(set_rules(@property_flush[:access_rules], 'access'))
    end
    if @property_flush[:audit_rules]
      Puppet.debug('Jack testing set_acl property_flush[:audit_rules]')

      ps(set_rules(@property_flush[:audit_rules], 'audit'))
    end
  end

  def flush
    Puppet.debug('Jack testing flush')

    set_acl

    # Collect the resources again once they've been changed (that way `puppet
    # resource` will show the correct values after changes have been made).
    @property_hash = self.class.get_acl(resource[:name])
  end

  def self.prefetch(resources)
    Puppet.debug('Jack testing self.prefetch(resources)')

    instances.each do |provider|
      resource = resources[provider.name]

      resource.provider = provider if resource
    end
  end

  def self.process_acl_xml(result)
    Puppet.debug('Jack testing self.process_acl_xml')

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
        audit_rule['identity'] = audit.xpath("./Property[@Name='IdentitySID']").text
        audit_rule['audit_flags'] = audit.xpath("./Property[@Name='AuditFlags']").text
        audit_rule['inheritance_type'] = audit.xpath("./Property[@Name='InheritanceType']").text

        audit_rules << audit_rule
      end

      access_rules = []

      object.xpath("./Property[@Name='Access']/Property").each do |access|
        access_rule = {}

        next if (access.xpath("./Property[@Name='ActiveDirectoryRights']").text == '') || (access.xpath("./Property[@Name='IsInherited']").text == 'True')
        access_rule['identity'] = access.xpath("./Property[@Name='IdentitySID']").text
        access_rule['ad_rights'] = access.xpath("./Property[@Name='ActiveDirectoryRights']").text
        access_rule['access_control_type'] = access.xpath("./Property[@Name='AccessControlType']").text
        access_rule['inheritance_type'] = access.xpath("./Property[@Name='InheritanceType']").text

        access_rules << access_rule
      end

      # put name and state into a hash
      acl_hash = {
        name: name.downcase,
        owner: owner,
        group: group,
        access_rules: access_rules,
        audit_rules: audit_rules,
      }

      # push hash to feature array
      acls.push(acl_hash)
    end

    acls
  end

  def self.get_acl(name)
    Puppet.debug('Jack testing self.get_acl')

    result = ps("Import-Module ActiveDirectory; Get-Acl -Path 'Microsoft.ActiveDirectory.Management\\ActiveDirectory:://RootDSE/#{name}' -Audit | ConvertTo-XML -As String -Depth 2 -NoTypeInformation")

    process_acl_xml(result)[0]
  end

  def self.instances
    Puppet.debug('Jack testing self.instances')

    query = ad_result_query
    result = ps(query)

    acls = process_acl_xml(result)

    # map the feature array
    acls.map do |acl|
      new(acl)
    end
  end
end
