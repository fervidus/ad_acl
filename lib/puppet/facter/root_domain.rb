Facter.add(:root_domain) do
  confine kernel: :windows

  setcode do
    require 'win32/registry'

    value = nil

    hive = Win32::Registry::HKEY_LOCAL_MACHINE
    hive.open('SYSTEM\CurrentControlSet\Services\NTDS\Parameters', Win32::Registry::KEY_READ) do |reg|
      value = reg['Root Domain']
    end

    value
  end
end
