# XSS attack detection
### This alert indicates that an XSS (Cross-Site Scripting) attack has been detected.
```json
{"id":"c2afc08f-f2af-4194-b010-678ca6645a3b","rule_id":"ab6db516-c340-4566-9468-42100c6f4fb9",
"name":"XSS Attack detected","immutable":false,"rule_source":{"type":"internal"},
"version":1,"revision":0,"updated_at":"2026-02-13T09:15:26.925Z",
"updated_by":"elastic","created_at":"2026-02-13T09:15:26.925Z","created_by":"elastic",
"enabled":true,"interval":"10m","from":"now-15m","to":"now","description":"This alert indicates that an XSS (Cross-Site Scripting) attack has been detected.",
"tags":["apache","web-server"],"author":["Saeed"],"license":"","threat":[{"framework":"MITRE ATT&CK","tactic":{"id":"TA0002","name":"Execution",
"reference":"https://attack.mitre.org/tactics/TA0002/"},"technique":[{"id":"T1059","name":"Command and Scripting Interpreter",
"reference":"https://attack.mitre.org/techniques/T1059/","subtechnique":[{"id":"T1059.007","name":"JavaScript",
"reference":"https://attack.mitre.org/techniques/T1059/007/"}]}]}],
"related_integrations":[],"required_fields":[],"setup":"","false_positives":[],
"references":[],"risk_score":47,"risk_score_mapping":[],
"severity":"medium","severity_mapping":[],"output_index":"",
"max_signals":10,"exceptions_list":[],"actions":[],"meta":{"kibana_siem_app_url":"http://192.168.1.50:5601/app/security"},
"type":"esql","language":"esql",
"query":"from logs-apache* METADATA _id, _index, _version \r\n| WHERE TO_LOWER(url.query) LIKE (\"*script*\", \"%3cscript\") \r\nOR TO_LOWER(message) LIKE \"*xss=20*\""}
{"exported_count":1,"exported_rules_count":1,"missing_rules":[],
"missing_rules_count":0,"exported_exception_list_count":0,
"exported_exception_list_item_count":0,"missing_exception_list_item_count":0,
"missing_exception_list_items":[],"missing_exception_lists":[],"missing_exception_lists_count":0,
"exported_action_connector_count":0,"missing_action_connection_count":0,"missing_action_connections":[],"excluded_action_connection_count":0,"excluded_action_connections":[]}

```
