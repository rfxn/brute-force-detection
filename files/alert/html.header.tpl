<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>BFD Alert for {{HOSTNAME}}</title>
</head>
<body style="margin:0;padding:0;background-color:#f5f5f5;font-family:Arial,Helvetica,sans-serif;font-size:14px;color:#333333;">
<table role="presentation" cellpadding="0" cellspacing="0" border="0" width="100%" style="background-color:#f5f5f5;">
<tr>
<td align="center" style="padding:20px 10px;">
<table role="presentation" cellpadding="0" cellspacing="0" border="0" width="600" style="max-width:600px;background-color:#ffffff;border:1px solid #dddddd;border-radius:4px;overflow:hidden;">
<!-- Banner -->
<tr>
<td style="background-color:#1a237e;padding:16px 20px;">
<table role="presentation" cellpadding="0" cellspacing="0" border="0" width="100%">
<tr>
<td style="color:#ffffff;font-size:20px;font-weight:bold;">BFD Alert</td>
<td align="right" style="color:#c5cae9;font-size:14px;">{{HOSTNAME}}</td>
</tr>
</table>
</td>
</tr>
<!-- Timestamp sub-bar -->
<tr>
<td style="background-color:#283593;padding:8px 20px;">
<table role="presentation" cellpadding="0" cellspacing="0" border="0" width="100%">
<tr>
<td style="color:#9fa8da;font-size:12px;">{{TIMESTAMP}} GMT {{TIME_ZONE}}</td>
<td align="right" style="color:#ffffff;font-size:12px;font-weight:bold;">{{ALERT_COUNT}} host(s) banned</td>
</tr>
</table>
</td>
</tr>
<!-- Content area (closed by footer) -->
<tr>
<td style="padding:20px;">
