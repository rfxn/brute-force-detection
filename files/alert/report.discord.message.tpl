{
	"embeds": [
		{
			"title": "BFD {{REPORT_INTERVAL_LABEL}} Threat Report",
			"description": "**{{HOSTNAME}}** | {{REPORT_DATE_RANGE}} ({{REPORT_WINDOW}})",
			"color": 3319890,
			"fields": [
				{
					"name": "Summary",
					"value": "**{{REPORT_UNIQUE_IPS}}** unique IPs | **{{REPORT_TOTAL_EVENTS}}** events | **{{REPORT_TOTAL_BANS}}** bans ({{REPORT_ACTIVE_BANS}} active)\nTrend: {{REPORT_TREND_LABEL}}",
					"inline": false
				},
				{
					"name": "Top Threats",
					"value": "{{REPORT_TOP_IPS_BRIEF_JSON}}",
					"inline": false
				},
				{
					"name": "Services",
					"value": "{{REPORT_SERVICES_BRIEF_JSON}}",
					"inline": false
				}
			],
			"footer": {
				"text": "BFD {{BFD_VERSION}} | rfxn.com"
			}
		}
	]
}
