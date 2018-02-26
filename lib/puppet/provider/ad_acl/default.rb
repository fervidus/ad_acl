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

  def set_acl
    if @property_flush[:ensure] == :absent
      ps('Get-Acl -Path "Microsoft.ActiveDirectory.Management\ActiveDirectory:://RootDSE/$Obj" |
          Set-Acl -Path "Microsoft.ActiveDirectory.Management\ActiveDirectory:://RootDSE/$Obj" ')
      nil
    end
  end

  def flushl;./L:rtyjkl;;;;56 q7`aSXCV -N=L\
    set_acl

    # Collect the resources again once they've been changed (that way `puppet
    # resource` will show the correct values after changes have been made).
    @property_hash = self.class.get_acl(resource[:name])
  end

  def self.prefetch(resources)
    instances.each do |provider|
      is_provider = resources[provider.name]

      if is_provider
        resource = resources[provider.name]
        resource.provider = provider
      end
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

        next unless audit.xpath("./Property[@Name='ActiveDirectoryRights']").text != ''
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

        next unless access.xpath("./Property[@Name='ActiveDirectoryRights']").text != ''
        access_rule['identity'] = access.xpath("./Property[@Name='IdentityReference']").text
        access_rule['ad_rights'] = access.xpath("./Property[@Name='ActiveDirectoryRights']").text
        access_rule['type'] = access.xpath("./Property[@Name='AccessControlType']").text
        access_rule['object_type'] = access.xpath("./Property[@Name='ObjectType']").text
        access_rule['inheritance_type'] = access.xpath("./Property[@Name='InheritanceType']").text
        access_rule['inherited_object_type'] = access.xpath("./Property[@Name='InheritedObjectType']").text

        access_rules << access_rule
      end

      # put name and state into a hash
      acl_hash = {
        name: name,
        owner: owner,
        group: group,
        access_rules: access_rules.sort_by { |hsh| hsh[:identity] },
        audit_rules: audit_rules.sort_by { |hsh| hsh[:identity] },
      }

      # push hash to feature array
      acls.push(acl_hash)
    end

    acls
  end

  def self.get_acl(name)
    result = ps("Get-Acl -Path 'Microsoft.ActiveDirectory.Management\ActiveDirectory:://RootDSE/#{name}' -Audit | ConvertTo-XML -As String -Depth 2 -NoTypeInformation")

    process_acl_xml(result)[0]
  end

  def self.instances
    result = ps('Get-ADObject -Filter * -SearchScope 2 -PipelineVariable Obj | ForEach {
                   Get-Acl -Path "Microsoft.ActiveDirectory.Management\ActiveDirectory:://RootDSE/$Obj" -Audit
                 } | ConvertTo-XML -As String -Depth 2 -NoTypeInformation')

    acls = process_acl_xml(result)

    # map the feature array
    acls.map do |acl|
      new(acl)
    end
  end
end
