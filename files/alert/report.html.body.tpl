<!-- Summary card -->
<tr><td style="padding:24px 32px;">
  <h2 style="margin:0 0 16px;font-size:16px;color:#111827;border-bottom:1px solid #e5e7eb;padding-bottom:8px;">Threat Summary</h2>
  <table role="presentation" width="100%" cellpadding="0" cellspacing="0">
  <tr>
    <td style="padding:8px 12px;background:#f0fdfa;border-radius:6px;text-align:center;width:25%;">
      <div style="font-size:24px;font-weight:700;color:#0d9488;">{{REPORT_UNIQUE_IPS}}</div>
      <div style="font-size:11px;color:#6b7280;margin-top:2px;">Unique IPs</div>
    </td>
    <td style="width:8px;"></td>
    <td style="padding:8px 12px;background:#f0fdfa;border-radius:6px;text-align:center;width:25%;">
      <div style="font-size:24px;font-weight:700;color:#0d9488;">{{REPORT_TOTAL_EVENTS}}</div>
      <div style="font-size:11px;color:#6b7280;margin-top:2px;">Events</div>
    </td>
    <td style="width:8px;"></td>
    <td style="padding:8px 12px;background:#f0fdfa;border-radius:6px;text-align:center;width:25%;">
      <div style="font-size:24px;font-weight:700;color:#0d9488;">{{REPORT_TOTAL_BANS}}</div>
      <div style="font-size:11px;color:#6b7280;margin-top:2px;">Bans</div>
    </td>
    <td style="width:8px;"></td>
    <td style="padding:8px 12px;background:#f0fdfa;border-radius:6px;text-align:center;width:25%;">
      <div style="font-size:24px;font-weight:700;color:#0d9488;">{{REPORT_ACTIVE_BANS}}</div>
      <div style="font-size:11px;color:#6b7280;margin-top:2px;">Active</div>
    </td>
  </tr>
  </table>
  <p style="margin:12px 0 0;font-size:13px;color:#4b5563;">Trend: {{REPORT_TREND_LABEL}}</p>
</td></tr>

<!-- Top IPs -->
<tr><td style="padding:0 32px 24px;">
  <h2 style="margin:0 0 12px;font-size:16px;color:#111827;border-bottom:1px solid #e5e7eb;padding-bottom:8px;">Top Threat IPs ({{REPORT_WINDOW}})</h2>
  {{REPORT_TOP_IPS_HTML}}
</td></tr>

<!-- Services -->
<tr><td style="padding:0 32px 24px;">
  <h2 style="margin:0 0 12px;font-size:16px;color:#111827;border-bottom:1px solid #e5e7eb;padding-bottom:8px;">Service Breakdown ({{REPORT_WINDOW}})</h2>
  {{REPORT_SERVICES_HTML}}
</td></tr>

<!-- Footer -->
<tr><td style="padding:16px 32px;background-color:#f9fafb;border-top:1px solid #e5e7eb;text-align:center;">
  <p style="margin:0;font-size:12px;color:#9ca3af;">BFD {{BFD_VERSION}} &middot; <a href="https://www.rfxn.com/projects/brute-force-detection" style="color:#0d9488;text-decoration:none;">rfxn.com</a> &middot; GNU GPL v2</p>
  <p style="margin:4px 0 0;font-size:11px;color:#d1d5db;">R-fx Networks &lt;proj@rfxn.com&gt;</p>
</td></tr>

</table>
</td></tr>
</table>
</body>
</html>
