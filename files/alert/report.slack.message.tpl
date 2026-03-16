{
	"blocks": [
		{
			"type": "header",
			"text": {
				"type": "plain_text",
				"text": "BFD {{REPORT_INTERVAL_LABEL}} Threat Report"
			}
		},
		{
			"type": "section",
			"text": {
				"type": "mrkdwn",
				"text": "*{{HOSTNAME}}* | {{REPORT_DATE_RANGE}} ({{REPORT_WINDOW}})\n*{{REPORT_UNIQUE_IPS}}* unique IPs . *{{REPORT_TOTAL_EVENTS}}* events . *{{REPORT_TOTAL_BANS}}* bans ({{REPORT_ACTIVE_BANS}} active)\nTrend: {{REPORT_TREND_LABEL}}"
			}
		},
		{
			"type": "divider"
		},
		{
			"type": "section",
			"text": {
				"type": "mrkdwn",
				"text": "*Top threats:*\n{{REPORT_TOP_IPS_BRIEF}}"
			}
		},
		{
			"type": "section",
			"text": {
				"type": "mrkdwn",
				"text": "*Services:*\n{{REPORT_SERVICES_BRIEF}}"
			}
		},
		{
			"type": "context",
			"elements": [
				{
					"type": "mrkdwn",
					"text": "BFD {{BFD_VERSION}} | <https://www.rfxn.com/projects/brute-force-detection|rfxn.com>"
				}
			]
		}
	]
}
