Puppet::Type.newtype(:ad_acl) do
  desc 'Manages the access control lists for an Active Directory controller'

  ensurable

  newparam(:path, namevar: true) do
    desc 'The path to the object on the active directory server'

    munge do |value|
      value.downcase
    end

    def insync?(is)
      is.casecmp(should.downcase).zero?
    end
  end

  newproperty(:user) do
    desc 'The user associated with this access control list'
  end

  newproperty(:group) do
    desc 'The group associated with this access control list'
  end

  newproperty(:audit_rules, array_matching: :all) do
    desc 'Audit rules associated with this acl'

    def insync?(is)
      is.sort == should.sort
    end
  end

  newproperty(:access_rules, array_matching: :all) do
    desc 'Access rules associated with this acl'

    def insync?(is)
      is.sort == should.sort
    end
  end
end
