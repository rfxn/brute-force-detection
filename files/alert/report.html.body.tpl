<!-- Summary card -->
<table role="presentation" cellpadding="0" cellspacing="0" border="0" width="100%" style="margin-bottom:16px;border:1px solid #d4d4d8;border-radius:8px;overflow:hidden;">
<!-- Accent top line -->
<tr>
<td style="background-color:#0891b2;height:3px;font-size:0;line-height:0;">&nbsp;</td>
</tr>
<!-- Summary header -->
<tr>
<td style="background-color:#f4f4f5;padding:10px 16px;border-bottom:1px solid #d4d4d8;">
<span style="font-size:11px;font-weight:bold;color:#52525b;text-transform:uppercase;letter-spacing:1px;">Threat Summary</span>
<span style="color:#71717a;font-size:11px;padding-left:8px;">{{REPORT_DATE_RANGE}}</span>
</td>
</tr>
<tr>
<td style="padding:12px 16px;">
<table role="presentation" cellpadding="0" cellspacing="0" border="0" width="100%" style="font-size:13px;">
<!-- Unique IPs / Total Events -->
<tr>
<td style="padding:4px 0;color:#71717a;width:50%;">Unique IPs</td>
<td style="padding:4px 0;font-weight:bold;color:#09090b;">{{REPORT_UNIQUE_IPS}}</td>
<td style="padding:4px 0;color:#71717a;width:25%;">Total events</td>
<td style="padding:4px 0;font-weight:bold;color:#09090b;">{{REPORT_TOTAL_EVENTS}}</td>
</tr>
<!-- Total Bans / Active Bans -->
<tr>
<td style="padding:4px 0;color:#71717a;">Total bans</td>
<td style="padding:4px 0;color:#0891b2;font-weight:bold;">{{REPORT_TOTAL_BANS}}</td>
<td style="padding:4px 0;color:#71717a;">Active bans</td>
<td style="padding:4px 0;color:#dc2626;font-weight:bold;">{{REPORT_ACTIVE_BANS}}</td>
</tr>
<!-- Temporary / Escalated -->
<tr>
<td style="padding:4px 0;color:#71717a;">Temporary</td>
<td style="padding:4px 0;color:#0891b2;font-weight:bold;">{{REPORT_TEMP_BANS}}</td>
<td style="padding:4px 0;color:#71717a;">Escalated</td>
<td style="padding:4px 0;color:#d97706;font-weight:bold;">{{REPORT_ESCALATIONS}}</td>
</tr>
<!-- Permanent / Repeat -->
<tr>
<td style="padding:4px 0;color:#71717a;">Permanent</td>
<td style="padding:4px 0;color:#dc2626;font-weight:bold;">{{REPORT_PERM_BANS}}</td>
<td style="padding:4px 0;color:#71717a;">Repeat offenders</td>
<td style="padding:4px 0;font-weight:bold;color:#09090b;">{{REPORT_REPEAT_OFFENDERS}} ({{REPORT_REPEAT_PCT}}%)</td>
</tr>
</table>
<!-- Separator -->
<table role="presentation" cellpadding="0" cellspacing="0" border="0" width="100%" style="margin:8px 0;">
<tr><td style="border-top:1px solid #d4d4d8;font-size:0;height:1px;">&nbsp;</td></tr>
</table>
<!-- Countries + Trend -->
<table role="presentation" cellpadding="0" cellspacing="0" border="0" width="100%" style="font-size:13px;">
<tr>
<td style="padding:4px 0;color:#71717a;width:100px;vertical-align:top;">Countries</td>
<td style="padding:4px 0;color:#09090b;">{{REPORT_TOP_COUNTRIES}}</td>
</tr>
<tr>
<td style="padding:4px 0;color:#71717a;vertical-align:top;">Trend</td>
<td style="padding:4px 0;color:#09090b;">{{REPORT_TREND_LABEL}}</td>
</tr>
</table>
</td>
</tr>
</table>

<!-- Top IPs card -->
<table role="presentation" cellpadding="0" cellspacing="0" border="0" width="100%" style="margin-bottom:16px;border:1px solid #d4d4d8;border-radius:8px;overflow:hidden;">
<tr>
<td style="background-color:#0891b2;height:3px;font-size:0;line-height:0;">&nbsp;</td>
</tr>
<tr>
<td style="background-color:#f4f4f5;padding:10px 16px;border-bottom:1px solid #d4d4d8;">
<span style="font-size:11px;font-weight:bold;color:#52525b;text-transform:uppercase;letter-spacing:1px;">Top Threat IPs ({{REPORT_WINDOW}})</span>
</td>
</tr>
<tr>
<td style="padding:4px 0;">
{{REPORT_TOP_IPS_HTML}}
</td>
</tr>
</table>

<!-- Services card -->
<table role="presentation" cellpadding="0" cellspacing="0" border="0" width="100%" style="margin-bottom:16px;border:1px solid #d4d4d8;border-radius:8px;overflow:hidden;">
<tr>
<td style="background-color:#0891b2;height:3px;font-size:0;line-height:0;">&nbsp;</td>
</tr>
<tr>
<td style="background-color:#f4f4f5;padding:10px 16px;border-bottom:1px solid #d4d4d8;">
<span style="font-size:11px;font-weight:bold;color:#52525b;text-transform:uppercase;letter-spacing:1px;">Service Breakdown ({{REPORT_WINDOW}})</span>
</td>
</tr>
<tr>
<td style="padding:4px 0;">
{{REPORT_SERVICES_HTML}}
</td>
</tr>
</table>

</td>
</tr>
<!-- Footer -->
<tr>
<td style="padding:16px 24px;border-top:1px solid #d4d4d8;">
<table role="presentation" cellpadding="0" cellspacing="0" border="0" width="100%">
<tr>
<td style="font-size:11px;color:#71717a;">
<span style="font-family:'Courier New',Courier,monospace;color:#0891b2;">R-fx Networks</span>
&nbsp;&middot;&nbsp;
BFD {{BFD_VERSION}}
&nbsp;&middot;&nbsp;
GPL v2
</td>
<td align="right" style="font-size:11px;">
<a href="https://www.rfxn.com/projects/brute-force-detection" style="color:#0891b2;text-decoration:none;">rfxn.com</a>
</td>
</tr>
</table>
</td>
</tr>
</table>
</td>
</tr>
</table>
</body>
</html>
