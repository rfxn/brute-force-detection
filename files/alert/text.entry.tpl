--- Ban {{ENTRY_NUM}} of {{ENTRY_TOTAL}} ------------------------------------------

  Host:        {{HOST}} ({{HOST_VERSION}}) {{COUNTRY_CODE}}
  Service:     {{SERVICE}} ({{PORTS}})
  Pressure:    {{FAIL_COUNT}} failed logins = +{{PRESSURE_CONTRIB}} this scan
               {{PRESSURE}} accumulated pressure * trips at {{PRESSURE_TRIP}} * weight {{WEIGHT}} * half-life {{HALF_LIFE_FMT}}
  Ban:         {{BAN_TYPE}}{{BAN_DURATION_DETAIL}}
{{HISTORY_LINE}}
{{ESCALATION_LINE}}
  Command:     {{BAN_COMMAND}}
{{REPUTATION_SECTION_TEXT}}
{{SOURCE_LOGS_SECTION_TEXT}}
