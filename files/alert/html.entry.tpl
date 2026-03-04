<!-- Entry card -->
<table role="presentation" cellpadding="0" cellspacing="0" border="0" width="100%" style="margin-bottom:16px;border:1px solid #e0e0e0;border-radius:4px;overflow:hidden;">
<!-- Entry header -->
<tr>
<td style="background-color:{{BAN_TYPE_COLOR}};padding:10px 14px;">
<table role="presentation" cellpadding="0" cellspacing="0" border="0" width="100%">
<tr>
<td style="color:#ffffff;font-size:14px;font-weight:bold;">{{COUNTRY_FLAG}} {{HOST}}</td>
<td align="right" style="color:#ffffff;font-size:12px;">{{BAN_TYPE}} ({{ENTRY_NUM}}/{{ENTRY_TOTAL}})</td>
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
<td style="padding:8px 14px 4px;color:#757575;width:100px;vertical-align:top;">Service</td>
<td style="padding:8px 14px 4px;">{{SERVICE}} ({{PORTS}})</td>
</tr>
<!-- Host -->
<tr>
<td style="padding:4px 14px;color:#757575;vertical-align:top;">Host</td>
<td style="padding:4px 14px;">{{HOST}} ({{HOST_VERSION}}) {{COUNTRY_CODE}}</td>
</tr>
<!-- Pressure -->
<tr>
<td style="padding:4px 14px;color:#757575;vertical-align:top;">Pressure</td>
<td style="padding:4px 14px;">
{{PRESSURE}}/{{PRESSURE_TRIP}} &mdash; weight {{WEIGHT}}, half-life {{HALF_LIFE_FMT}}
<table role="presentation" cellpadding="0" cellspacing="0" border="0" width="100%" style="margin-top:4px;">
<tr>
<td style="background-color:#eeeeee;border-radius:3px;padding:0;">
<table role="presentation" cellpadding="0" cellspacing="0" border="0" style="width:{{PRESSURE_PCT_CLAMPED}}%;min-width:1px;">
<tr>
<td style="background-color:{{PRESSURE_COLOR}};height:8px;border-radius:3px;">&nbsp;</td>
</tr>
</table>
</td>
<td style="width:45px;padding-left:6px;font-size:11px;color:#757575;white-space:nowrap;">{{PRESSURE_PCT}}%</td>
</tr>
</table>
</td>
</tr>
<!-- Ban -->
<tr>
<td style="padding:4px 14px;color:#757575;vertical-align:top;">Ban</td>
<td style="padding:4px 14px;">{{BAN_TYPE}}{{BAN_DURATION_DETAIL}}</td>
</tr>
{{HISTORY_ROW_HTML}}
{{ESCALATION_ROW_HTML}}
<!-- Command -->
<tr>
<td style="padding:4px 14px;color:#757575;vertical-align:top;">Command</td>
<td style="padding:4px 14px;"><code style="font-size:12px;background-color:#f5f5f5;padding:2px 6px;border-radius:2px;">{{BAN_COMMAND}}</code></td>
</tr>
{{REPUTATION_SECTION_HTML}}
{{SOURCE_LOGS_SECTION_HTML}}
</table>
</td>
</tr>
</table>
