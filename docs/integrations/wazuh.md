# Wazuh integration

Wazuh agent can ingest kernelradar alerts in two ways:

## Option A: Watch journald (recommended)

```xml
<!-- /var/ossec/etc/ossec.conf -->
<localfile>
  <log_format>journald</log_format>
  <location>kernelradar</location>
</localfile>
```

Wazuh pulls JSON-structured kernelradar alerts directly from journald.
Each `F_DETECTOR`, `F_SEVERITY`, `F_PID`, `F_COMM`, `F_CORRELATION_ID`
journal field becomes a JSON field that Wazuh rules can match.

## Option B: Watch a JSON file

```bash
# kernelradar in JSON mode → file
kernelradar --format=json daemon > /var/log/kernelradar.json
```

```xml
<!-- /var/ossec/etc/ossec.conf -->
<localfile>
  <log_format>json</log_format>
  <location>/var/log/kernelradar.json</location>
</localfile>
```

## Sample Wazuh rule

`/var/ossec/etc/rules/local_rules.xml`:

```xml
<group name="kernelradar,">

  <rule id="200001" level="10">
    <decoded_as>json</decoded_as>
    <field name="detector">privesc</field>
    <field name="severity">Alert|Critical</field>
    <description>kernelradar: privilege escalation detected</description>
  </rule>

  <rule id="200002" level="12">
    <decoded_as>json</decoded_as>
    <field name="detector">cred</field>
    <field name="severity">Critical</field>
    <description>kernelradar: credential file accessed</description>
  </rule>

  <rule id="200003" level="13">
    <decoded_as>json</decoded_as>
    <field name="detector">network.burst</field>
    <description>kernelradar: BURST of public network connections</description>
  </rule>

</group>
```

Levels follow Wazuh convention (10 = Alert, 12 = High, 13 = Critical).
