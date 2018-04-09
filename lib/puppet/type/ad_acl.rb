Puppet::Type.newtype(:ad_acl) do
  desc 'Manages the access control lists for an Active Directory controller'

  # ensurable

  newparam(:name, namevar: true) do
    desc 'The path to the object on the active directory server'
    Puppet.debug('Jack testing namevar')

    munge(&:downcase)

    def insync?(is)
      is.casecmp(should.downcase).zero?
    end
  end

  newproperty(:owner) do
    desc 'The user associated with this access control list'
    Puppet.debug('Jack testing owner')


    def insync?(is)
      is.casecmp(should.downcase).zero?
    end
  end

  newproperty(:group) do
    desc 'The group associated with this access control list'
    Puppet.debug('Jack testing group')


    def insync?(is)
      is.casecmp(should.downcase).zero?
    end
  end

  newproperty(:audit_rules, array_matching: :all) do
    desc 'Audit rules associated with this acl'
    Puppet.debug('Jack testing audit_rules')


    validate do |value|
      unless /^S-\d-(\d+-){1,14}\d+$/.match(value['identity'])
        raise ArgumentError,
          "Audit rules currently only accept SIDs as identifiers"
      else
        value
      end
    end

    def insync?(is)
      is_sort = is.sort do |a, b|
        [
          a['identity'],
          a['ad_rights'],
          a['audit_flags'],
          a['inheritance_type'],
        ] <=> [
          b['identity'],
          b['ad_rights'],
          b['audit_flags'],
          b['inheritance_type'],
        ]
      end

      should_sort = should.sort do |a, b|
        [
          a['identity'],
          a['ad_rights'],
          a['audit_flags'],
          a['inheritance_type'],
        ] <=> [
          b['identity'],
          b['ad_rights'],
          b['audit_flags'],
          b['inheritance_type'],
        ]
      end

      is_sort == should_sort
    end
  end

  newproperty(:access_rules, array_matching: :all) do
    desc 'Access rules associated with this acl'
    Puppet.debug('Jack testing access_rules')


    validate do |value|
      unless /^S-\d-\d+-(\d+-){1,14}\d+$/.match(value['identity'])
        raise ArgumentError,
          "Access rules currently only accept SIDs as identifiers"
      else
        value
      end
    end

    def insync?(is)
      is_sort = is.sort do |a, b|
        [
          a['identity'],
          a['ad_rights'],
          a['access_control_type'],
          a['inheritance_type'],
        ] <=> [
          b['identity'],
          b['ad_rights'],
          b['access_control_type'],
          b['inheritance_type'],
        ]
      end

      should_sort = should.sort do |a, b|
        [
          a['identity'],
          a['ad_rights'],
          a['access_control_type'],
          a['inheritance_type'],
        ] <=> [
          b['identity'],
          b['ad_rights'],
          b['access_control_type'],
          b['inheritance_type'],
        ]
      end

      is_sort == should_sort
    end
  end
end
