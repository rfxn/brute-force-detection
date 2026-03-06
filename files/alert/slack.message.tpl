{
	"blocks": [
		{
			"type": "header",
			"text": {
				"type": "plain_text",
				"text": "BFD Alert: {{HOSTNAME}}"
			}
		},
		{
			"type": "section",
			"text": {
				"type": "mrkdwn",
				"text": "*{{ALERT_COUNT}}* host(s) banned  |  {{TIMESTAMP}} GMT {{TIME_ZONE}}"
			}
		},
{{ENTRY_BLOCKS}}
		{
			"type": "divider"
		},
		{
			"type": "context",
			"elements": [
				{
					"type": "mrkdwn",
					"text": "{{SUMMARY_TOTAL_BANS}} bans ({{SUMMARY_UNIQUE_IPS}} unique) | {{SUMMARY_SERVICES}} | {{SUMMARY_TEMPORARY}} temp, {{SUMMARY_ESCALATED}} esc, {{SUMMARY_PERMANENT}} perm | {{SUMMARY_REPEAT_OFFENDERS}} repeat ({{SUMMARY_REPEAT_PCT}}%)"
				}
			]
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
