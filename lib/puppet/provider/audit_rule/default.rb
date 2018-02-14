require 'rexml/document'
include REXML

Puppet::Type.type(:windowsfeature).provide(:default) do
  # We don't support 1.8.7 officially, but lets be nice and not cause errors
  # rubocop:disable Style/HashSyntax

  # windows only
  confine :kernel => :windows
  # powershell, powershell, powershell.  where to find it.
  commands :ps =>
    if File.exist?("#{ENV['SYSTEMROOT']}\\sysnative\\WindowsPowershell\\v1.0\\powershell.exe")
      "#{ENV['SYSTEMROOT']}\\sysnative\\WindowsPowershell\\v1.0\\powershell.exe"
    elsif File.exist?("#{ENV['SYSTEMROOT']}\\system32\\WindowsPowershell\\v1.0\\powershell.exe")
      "#{ENV['SYSTEMROOT']}\\system32\\WindowsPowershell\\v1.0\\powershell.exe"
    else
      'powershell.exe'
    end

  def self.instances
    # an array to store feature hashes
    acls = []
    result = ps('Get-ADObject -Identity "CN=RID Manager$,CN=System,DC=autostructure,DC=io" -PipelineVariable Obj | ForEach {
                  Get-Acl -Path "Microsoft.ActiveDirectory.Management\ActiveDirectory:://RootDSE/$Obj" -Audit
                } | ConvertTo-XML -As String -Depth 2 -NoTypeInformation')
    # create the XML document and parse the objects
    xml = Document.new result
    xml.root.each_element do |object|
      # get the name and install state of the windows feature
      # name  = object.elements["Property[@Name='Name']"].text.downcase
      # state = if object.elements["Property[@Name='Installed']"].text == 'False'
      #           :absent
      #         elsif object.elements["Property[@Name='Installed']"].text == 'True'
      #          :present
      #        end
      owner = object.elements["Property[@Name='Owner']"].text.downcase
      group = object.elements["Property[@Name='Group']"].text.downcase

      audit_rules = []

      object.elements["Property[@Name='Audit']"].each_element do |audit|
        audit_rule = {}

        audit_rule['ad_rights'] = audit.elements["Property[@Name='ActiveDirectoryRights']"]
        audit_rule['identity'] = audit.elements["Property[@Name='IdentityReference']"]
        audit_rule['audit_flags'] = audit.elements["Property[@Name='AuditFlags']"]
        audit_rule['inheritance_type'] = audit.elements["Property[@Name='InheritanceType']"]
        audit_rule['object_type'] = audit.elements["Property[@Name='ObjectType']"]
        audit_rule['inherited_object_type'] = audit.elements["Property[@Name='InheritedObjectType']"]

        audit_rules << audit_rule
      end

      access_rules = []

      object.elements["Property[@Name='Access']"].each_element do |access|
        access_rule = {}

        access_rule['identity'] = access.elements["Property[@Name='IdentityReference']"]
        access_rule['ad_rights'] = access.elements["Property[@Name='ActiveDirectoryRights']"]
        access_rule['type'] = access.elements["Property[@Name='AccessControlType']"]
        access_rule['object_type'] = access.elements["Property[@Name='ObjectType']"]
        access_rule['inheritance_type'] = access.elements["Property[@Name='InheritanceType']"]
        access_rule['inherited_object_type'] = access.elements["Property[@Name='InheritedObjectType']"]

        access_rules << access_rule
      end

      # put name and state into a hash
      acl_hash = {
        :owner => owner,
        :group => group,
        :access_rules => access_rules,
        :audit_rules => audit_rules,
      }
      # push hash to feature array
      acls.push(acl_hash)
    end
    # map the feature array
    acls.map do |feature|
      new(feature)
    end
  end
end
