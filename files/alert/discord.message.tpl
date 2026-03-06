{
	"embeds": [
		{
			"title": "BFD Alert: {{HOSTNAME}}",
			"description": "**{{ALERT_COUNT}}** host(s) banned | {{TIMESTAMP}} GMT {{TIME_ZONE}}",
			"color": 3319890,
			"fields": [
{{ENTRY_FIELDS}}
				{
					"name": "Summary",
					"value": "{{SUMMARY_TOTAL_BANS}} bans ({{SUMMARY_UNIQUE_IPS}} unique) | {{SUMMARY_SERVICES}}\n{{SUMMARY_TEMPORARY}} temp, {{SUMMARY_ESCALATED}} esc, {{SUMMARY_PERMANENT}} perm | {{SUMMARY_REPEAT_OFFENDERS}} repeat ({{SUMMARY_REPEAT_PCT}}%)",
					"inline": false
				}
			],
			"footer": {
				"text": "BFD {{BFD_VERSION}} | rfxn.com"
			}
		}
	]
}
