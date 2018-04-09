Facter.add(:root_domain) do
  confine kernel: :windows

  setcode do
    require 'win32/registry'

    # Check if the machine is a Domain Controller
    value = nil
    val = nil
    type = Win32::Registry::HKEY_LOCAL_MACHINE
    type.open('SYSTEM\CurrentControlSet\Control\ProductOptions', Win32::Registry::KEY_READ) do |r|
      val = r['ProductType']
    end

    # If the machine is a DC, it is safe to open this key without errors
    if val == 'LanmanNT'
      hive = Win32::Registry::HKEY_LOCAL_MACHINE
      hive.open('SYSTEM\CurrentControlSet\Services\NTDS\Parameters', Win32::Registry::KEY_READ) do |reg|
        value = reg['Root Domain']
      end
    end
    value
  end
end
