<!-- Entry card -->
<table role="presentation" cellpadding="0" cellspacing="0" border="0" width="100%" style="margin-bottom:16px;border:1px solid #d4d4d8;border-radius:8px;overflow:hidden;">
<!-- Severity top line -->
<tr>
<td style="background-color:{{BAN_TYPE_COLOR}};height:3px;font-size:0;line-height:0;">&nbsp;</td>
</tr>
<!-- Entry header -->
<tr>
<td style="background-color:#f4f4f5;padding:10px 16px;border-bottom:1px solid #d4d4d8;">
<table role="presentation" cellpadding="0" cellspacing="0" border="0" width="100%">
<tr>
<td style="font-family:'Courier New',Courier,monospace;font-size:14px;font-weight:bold;color:#09090b;">{{COUNTRY_FLAG}} {{HOST}}</td>
<td align="right" style="white-space:nowrap;">
<span style="display:inline-block;background-color:{{BAN_TYPE_COLOR}};color:#ffffff;padding:2px 10px;border-radius:10px;font-size:11px;font-weight:bold;font-family:'Courier New',Courier,monospace;">{{BAN_TYPE}}</span>
<span style="color:#71717a;font-size:11px;padding-left:4px;">{{ENTRY_NUM}}/{{ENTRY_TOTAL}}</span>
</td>
</tr>
</table>
</td>
</tr>
<!-- Detail rows -->
<tr>
<td style="padding:0;">
<table role="presentation" cellpadding="0" cellspacing="0" border="0" width="100%" style="font-size:13px;">
<!-- Service -->
<tr>
<td style="padding:10px 16px 4px;color:#71717a;width:100px;vertical-align:top;">Service</td>
<td style="padding:10px 16px 4px;color:#09090b;">{{SERVICE}} ({{PORTS}})</td>
</tr>
<!-- Host -->
<tr>
<td style="padding:4px 16px;color:#71717a;vertical-align:top;">Host</td>
<td style="padding:4px 16px;color:#09090b;">{{HOST}} ({{HOST_VERSION}}) {{COUNTRY_CODE}}</td>
</tr>
<!-- Pressure -->
<tr>
<td style="padding:4px 16px;color:#71717a;vertical-align:top;">Pressure</td>
<td style="padding:4px 16px;color:#09090b;">
<span style="font-size:13px;font-weight:bold;color:#09090b;">{{FAIL_COUNT}} failed logins = +{{PRESSURE_CONTRIB}} this scan</span>
<br>
<span style="font-size:12px;color:#71717a;">{{PRESSURE}} accumulated pressure &middot; trips at {{PRESSURE_TRIP}} &middot; weight {{WEIGHT}} &middot; half-life {{HALF_LIFE_FMT}}</span>
</td>
</tr>
<!-- Ban -->
<tr>
<td style="padding:4px 16px;color:#71717a;vertical-align:top;">Ban</td>
<td style="padding:4px 16px;color:#09090b;">{{BAN_TYPE}}{{BAN_DURATION_DETAIL}}</td>
</tr>
{{HISTORY_ROW_HTML}}
{{ESCALATION_ROW_HTML}}
<!-- Command -->
<tr>
<td style="padding:4px 16px;color:#71717a;vertical-align:top;">Command</td>
<td style="padding:4px 16px;"><code style="font-family:'Courier New',Courier,monospace;font-size:12px;background-color:#f4f4f5;padding:2px 6px;border-radius:4px;border:1px solid #d4d4d8;">{{BAN_COMMAND}}</code></td>
</tr>
{{REPUTATION_SECTION_HTML}}
{{SOURCE_LOGS_SECTION_HTML}}
</table>
</td>
</tr>
</table>
