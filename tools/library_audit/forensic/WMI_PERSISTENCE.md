# FORENSIC_WMI_PERSISTENCE (Forensic.Windows.WMIPersistence)

- Captures: WMI permanent event subscriptions carved from the WMI repository `C:/Windows/System32/wbem/Repository/OBJECTS.DATA`. Three sources: FilterToConsumerBinding (consumer type/name + bound filter name + the filter's WQL query), EventFilters (filter name + WQL query), Consumers (every consumer instance + script/command body for scripted consumers).
- Mode: file (runs under the dead-disk remap; reads the OBJECTS.DATA file).
- Rows on P:: 3 (1 binding + 1 filter + 1 consumer) - the benign default "SCM Event Log Consumer" / "SCM Event Log Filter" subscription present on every clean Windows (query `select * from MSFT_SCMEventLogEvent`). No scripted (ActiveScript/CommandLine) consumer on this clean image, so ScriptOrCommand is null (that field is the ATT&CK T1546.003 payload).
- Built-in used: none for the dead disk. The built-in `Windows.Persistence.PermanentWMIEvents` uses the live `wmi()` plugin (disabled by the remap, and it would read the analyst host, not the image), so this artifact carves OBJECTS.DATA with `parse_records_with_regex` instead - the standard dead-disk WMI technique.
