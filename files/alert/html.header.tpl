<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>BFD Alert for {{HOSTNAME}}</title>
</head>
<body style="margin:0;padding:0;background-color:#f4f4f5;font-family:Arial,Helvetica,sans-serif;font-size:14px;color:#09090b;">
<table role="presentation" cellpadding="0" cellspacing="0" border="0" width="100%" style="background-color:#f4f4f5;">
<tr>
<td align="center" style="padding:20px 10px;">
<table role="presentation" cellpadding="0" cellspacing="0" border="0" width="600" style="max-width:600px;background-color:#ffffff;border:1px solid #d4d4d8;border-radius:8px;overflow:hidden;">
<!-- Teal brand bar -->
<tr>
<td style="background-color:#0891b2;padding:20px 24px 18px;">
<table role="presentation" cellpadding="0" cellspacing="0" border="0" width="100%">
<tr>
<td>
<span style="font-family:'Courier New',Courier,monospace;font-size:20px;font-weight:bold;color:#ffffff;letter-spacing:-0.5px;">rfxn</span>
<span style="color:rgba(255,255,255,0.4);padding:0 8px;font-size:18px;">|</span>
<span style="font-family:'Courier New',Courier,monospace;font-size:10px;font-weight:bold;color:rgba(255,255,255,0.7);text-transform:uppercase;letter-spacing:2px;">brute force detection</span>
</td>
<td align="right" style="font-family:'Courier New',Courier,monospace;color:#ffffff;font-size:12px;">{{HOSTNAME}}</td>
</tr>
</table>
</td>
</tr>
<!-- Accent sub-line -->
<tr>
<td style="background-color:#0e7490;height:2px;font-size:0;line-height:0;">&nbsp;</td>
</tr>
<!-- Meta bar -->
<tr>
<td style="background-color:#f4f4f5;padding:10px 24px;border-bottom:1px solid #d4d4d8;">
<table role="presentation" cellpadding="0" cellspacing="0" border="0" width="100%">
<tr>
<td style="color:#52525b;font-size:12px;font-family:'Courier New',Courier,monospace;">{{TIMESTAMP}} GMT {{TIME_ZONE}}</td>
<td align="right" style="font-size:11px;">
<span style="display:inline-block;background-color:#0891b2;color:#ffffff;padding:2px 10px;border-radius:10px;font-weight:bold;font-family:'Courier New',Courier,monospace;">{{ALERT_COUNT}} banned</span>
</td>
</tr>
</table>
</td>
</tr>
<!-- Content area (closed by footer) -->
<tr>
<td style="padding:20px 24px;">
