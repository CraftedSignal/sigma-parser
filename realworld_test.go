package sigma

import (
	"testing"
)

// Real-world Sigma rules from SigmaHQ and common detection use cases.
// Each test verifies the parser handles real detection logic correctly.

var realWorldRules = []struct {
	name     string
	yaml     string
	wantErr  bool
	validate func(t *testing.T, r *ParseResult)
}{
	{
		name: "process_creation_mimikatz",
		yaml: `
title: Mimikatz Detection
status: stable
level: critical
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        - Image|endswith: '\mimikatz.exe'
        - OriginalFileName: 'mimikatz.exe'
        - CommandLine|contains:
            - 'sekurlsa::'
            - 'kerberos::'
            - 'crypto::'
            - 'lsadump::'
    condition: selection
tags:
    - attack.credential_access
    - attack.t1003.001
`,
		validate: func(t *testing.T, r *ParseResult) {
			if r.Level != "critical" {
				t.Errorf("expected level critical, got %q", r.Level)
			}
			if r.LogSource == nil || r.LogSource.Category != "process_creation" {
				t.Error("expected logsource category process_creation")
			}
			if len(r.Conditions) == 0 {
				t.Error("expected conditions")
			}
		},
	},
	{
		name: "windows_event_log_clearing",
		yaml: `
title: Windows Event Log Cleared
status: stable
level: high
logsource:
    product: windows
    service: system
detection:
    selection:
        EventID: 104
        Provider_Name: 'Microsoft-Windows-Eventlog'
    condition: selection
tags:
    - attack.defense_evasion
    - attack.t1070.001
`,
		validate: func(t *testing.T, r *ParseResult) {
			found104 := false
			for _, c := range r.Conditions {
				if c.Field == "EventID" && c.Value == "104" {
					found104 = true
				}
			}
			if !found104 {
				t.Error("expected EventID=104")
			}
		},
	},
	{
		name: "suspicious_powershell_download",
		yaml: `
title: Suspicious PowerShell Download
status: test
level: medium
logsource:
    category: process_creation
    product: windows
detection:
    selection_img:
        Image|endswith:
            - '\powershell.exe'
            - '\pwsh.exe'
    selection_cli:
        CommandLine|contains|all:
            - 'Net.WebClient'
            - 'DownloadString'
    condition: selection_img and selection_cli
`,
		validate: func(t *testing.T, r *ParseResult) {
			if len(r.Conditions) < 3 {
				t.Errorf("expected at least 3 conditions, got %d", len(r.Conditions))
			}
		},
	},
	{
		name: "lateral_movement_psexec",
		yaml: `
title: PsExec Tool Execution
status: stable
level: medium
logsource:
    category: process_creation
    product: windows
detection:
    selection_svc:
        ParentImage|endswith: '\services.exe'
        Image|endswith: '\PSEXESVC.exe'
    selection_cli:
        Image|endswith:
            - '\psexec.exe'
            - '\psexec64.exe'
    condition: selection_svc or selection_cli
`,
		validate: func(t *testing.T, r *ParseResult) {
			if len(r.Conditions) < 2 {
				t.Error("expected at least 2 conditions")
			}
		},
	},
	{
		name: "windows_defender_disabled",
		yaml: `
title: Windows Defender Disabled
status: test
level: high
logsource:
    product: windows
    service: windefend
detection:
    selection:
        EventID:
            - 5001
            - 5010
            - 5012
    condition: selection
`,
		validate: func(t *testing.T, r *ParseResult) {
			found := false
			for _, c := range r.Conditions {
				if c.Field == "EventID" && len(c.Alternatives) == 3 {
					found = true
				}
			}
			if !found {
				t.Error("expected EventID with 3 alternatives")
			}
		},
	},
	{
		name: "brute_force_with_aggregation",
		yaml: `
title: Multiple Failed Logins
status: test
level: medium
logsource:
    product: windows
    service: security
detection:
    selection:
        EventID: 4625
    timeframe: 5m
    condition: selection | count() by SourceIP > 10
`,
		validate: func(t *testing.T, r *ParseResult) {
			if len(r.Commands) == 0 || r.Commands[0] != "count" {
				t.Errorf("expected count command, got %v", r.Commands)
			}
			if len(r.GroupByFields) != 1 || r.GroupByFields[0] != "SourceIP" {
				t.Errorf("expected GroupByFields [SourceIP], got %v", r.GroupByFields)
			}
		},
	},
	{
		name: "sysmon_file_creation",
		yaml: `
title: Suspicious File Creation in Temp
status: test
level: medium
logsource:
    category: file_event
    product: windows
detection:
    selection:
        TargetFilename|startswith:
            - 'C:\Windows\Temp\'
            - 'C:\Users\'
        TargetFilename|endswith:
            - '.exe'
            - '.dll'
            - '.bat'
            - '.ps1'
    filter:
        Image|startswith:
            - 'C:\Windows\System32\'
            - 'C:\Program Files\'
    condition: selection and not filter
`,
		validate: func(t *testing.T, r *ParseResult) {
			negatedCount := 0
			for _, c := range r.Conditions {
				if c.Negated {
					negatedCount++
				}
			}
			if negatedCount == 0 {
				t.Error("expected negated conditions from filter")
			}
		},
	},
	{
		name: "network_connection_suspicious_port",
		yaml: `
title: Connection to Suspicious Port
status: test
level: low
logsource:
    category: network_connection
    product: windows
detection:
    selection:
        Initiated: 'true'
        DestinationPort:
            - 4444
            - 5555
            - 1337
            - 31337
    condition: selection
`,
		validate: func(t *testing.T, r *ParseResult) {
			foundPort := false
			for _, c := range r.Conditions {
				if c.Field == "DestinationPort" && len(c.Alternatives) > 0 {
					foundPort = true
				}
			}
			if !foundPort {
				t.Error("expected DestinationPort with alternatives")
			}
		},
	},
	{
		name: "registry_modification",
		yaml: `
title: Registry Run Key Modification
status: stable
level: medium
logsource:
    category: registry_set
    product: windows
detection:
    selection:
        TargetObject|contains:
            - '\SOFTWARE\Microsoft\Windows\CurrentVersion\Run'
            - '\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce'
    filter_legitimate:
        Image|startswith:
            - 'C:\Windows\System32\'
            - 'C:\Program Files\'
            - 'C:\Program Files (x86)\'
    condition: selection and not filter_legitimate
`,
		validate: func(t *testing.T, r *ParseResult) {
			if len(r.Conditions) < 2 {
				t.Error("expected at least 2 conditions")
			}
		},
	},
	{
		name: "dns_query_suspicious",
		yaml: `
title: DNS Query to Suspicious TLD
status: test
level: low
logsource:
    category: dns_query
    product: windows
detection:
    selection:
        QueryName|endswith:
            - '.xyz'
            - '.top'
            - '.club'
            - '.online'
            - '.icu'
    condition: selection
`,
		validate: func(t *testing.T, r *ParseResult) {
			found := false
			for _, c := range r.Conditions {
				if c.Field == "QueryName" && c.Operator == "endswith" {
					found = true
				}
			}
			if !found {
				t.Error("expected QueryName endswith condition")
			}
		},
	},
	{
		name: "all_of_pattern",
		yaml: `
title: All Detection Criteria
status: test
level: high
logsource:
    category: process_creation
    product: windows
detection:
    selection_process:
        Image|endswith: '\rundll32.exe'
    selection_cmdline:
        CommandLine|contains: 'javascript:'
    condition: all of selection_*
`,
		validate: func(t *testing.T, r *ParseResult) {
			if len(r.Conditions) < 2 {
				t.Error("expected at least 2 conditions from all of selection_*")
			}
		},
	},
	{
		name: "1_of_them",
		yaml: `
title: Any Detection Match
status: test
level: medium
logsource:
    category: process_creation
    product: windows
detection:
    selection1:
        Image|endswith: '\certutil.exe'
    selection2:
        Image|endswith: '\bitsadmin.exe'
    selection3:
        Image|endswith: '\mshta.exe'
    condition: 1 of them
`,
		validate: func(t *testing.T, r *ParseResult) {
			if len(r.Conditions) < 1 {
				t.Error("expected at least 1 condition from 1 of them")
			}
		},
	},
	{
		name: "complex_nested_logic",
		yaml: `
title: Complex Nested Detection
status: test
level: high
logsource:
    category: process_creation
    product: windows
detection:
    selection_parent:
        ParentImage|endswith:
            - '\cmd.exe'
            - '\powershell.exe'
    selection_child:
        Image|endswith: '\whoami.exe'
    selection_net:
        Image|endswith: '\net.exe'
        CommandLine|contains:
            - ' user '
            - ' localgroup '
    filter:
        User: 'SYSTEM'
    condition: selection_parent and (selection_child or selection_net) and not filter
`,
		validate: func(t *testing.T, r *ParseResult) {
			if len(r.Conditions) < 3 {
				t.Error("expected at least 3 conditions")
			}
			foundFilter := false
			for _, c := range r.Conditions {
				if c.Field == "User" && c.Negated {
					foundFilter = true
				}
			}
			if !foundFilter {
				t.Error("expected negated User condition")
			}
		},
	},
	{
		name: "cidr_detection",
		yaml: `
title: Connection to Known C2 Ranges
status: test
level: high
logsource:
    category: network_connection
    product: windows
detection:
    selection:
        DestinationIp|cidr:
            - '185.220.100.0/24'
            - '91.219.237.0/24'
    condition: selection
`,
		validate: func(t *testing.T, r *ParseResult) {
			found := false
			for _, c := range r.Conditions {
				if c.Operator == "cidrmatch" {
					found = true
				}
			}
			if !found {
				t.Error("expected cidrmatch operator")
			}
		},
	},
	{
		name: "regex_detection",
		yaml: `
title: Regex Pattern Match
status: test
level: medium
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        CommandLine|re: '(?i).*\\(invoke|iex).*downloadstring.*'
    condition: selection
`,
		validate: func(t *testing.T, r *ParseResult) {
			found := false
			for _, c := range r.Conditions {
				if c.Operator == "matches" {
					found = true
				}
			}
			if !found {
				t.Error("expected matches operator for regex")
			}
		},
	},
	{
		name: "sysmon_driver_load",
		yaml: `
title: Suspicious Driver Loaded
status: test
level: high
logsource:
    category: driver_load
    product: windows
detection:
    selection:
        ImageLoaded|endswith:
            - '\WinDivert.sys'
            - '\WinDivert64.sys'
            - '\npf.sys'
    condition: selection
`,
		validate: func(t *testing.T, r *ParseResult) {
			found := false
			for _, c := range r.Conditions {
				if c.Field == "ImageLoaded" && len(c.Alternatives) == 3 {
					found = true
				}
			}
			if !found {
				t.Error("expected ImageLoaded with 3 alternatives")
			}
		},
	},
	{
		name: "linux_process_creation",
		yaml: `
title: Suspicious Linux Command
status: test
level: medium
logsource:
    category: process_creation
    product: linux
detection:
    selection:
        Image|endswith:
            - '/nc'
            - '/ncat'
            - '/netcat'
        CommandLine|contains:
            - '-e /bin/sh'
            - '-e /bin/bash'
    condition: selection
`,
		validate: func(t *testing.T, r *ParseResult) {
			if r.LogSource.Product != "linux" {
				t.Errorf("expected linux product, got %q", r.LogSource.Product)
			}
		},
	},
	{
		name: "proxy_webshell_user_agent",
		yaml: `
title: Webshell User Agent
status: test
level: high
logsource:
    category: proxy
detection:
    selection:
        c-useragent|contains:
            - 'python-requests'
            - 'Go-http-client'
            - 'curl/'
            - 'wget/'
    condition: selection
`,
		validate: func(t *testing.T, r *ParseResult) {
			found := false
			for _, c := range r.Conditions {
				if c.Field == "c-useragent" && c.Operator == "contains" {
					found = true
				}
			}
			if !found {
				t.Error("expected c-useragent contains condition")
			}
		},
	},
	{
		name: "aws_cloudtrail_root_login",
		yaml: `
title: AWS Root Account Login
status: stable
level: high
logsource:
    product: aws
    service: cloudtrail
detection:
    selection:
        eventSource: 'signin.amazonaws.com'
        eventName: 'ConsoleLogin'
        userIdentity.type: 'Root'
    condition: selection
`,
		validate: func(t *testing.T, r *ParseResult) {
			if r.LogSource.Product != "aws" {
				t.Error("expected aws product")
			}
			foundRoot := false
			for _, c := range r.Conditions {
				if c.Field == "userIdentity.type" && c.Value == "Root" {
					foundRoot = true
				}
			}
			if !foundRoot {
				t.Error("expected userIdentity.type=Root")
			}
		},
	},
	{
		name: "windash_modifier",
		yaml: `
title: Windash Test
status: test
level: medium
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        CommandLine|windash|contains:
            - '-exec bypass'
            - '-nop'
    condition: selection
`,
		validate: func(t *testing.T, r *ParseResult) {
			if len(r.Conditions) == 0 {
				t.Error("expected conditions")
			}
		},
	},
	{
		name: "multiple_detection_blocks",
		yaml: `
title: Multiple Blocks
status: test
level: medium
logsource:
    category: process_creation
    product: windows
detection:
    selection_img:
        Image|endswith: '\csc.exe'
    selection_parent:
        ParentImage|endswith:
            - '\powershell.exe'
            - '\cmd.exe'
    filter_legit:
        CommandLine|contains: 'Microsoft.NET'
    filter_user:
        User|startswith: 'NT AUTHORITY'
    condition: (selection_img and selection_parent) and not (filter_legit or filter_user)
`,
		validate: func(t *testing.T, r *ParseResult) {
			if len(r.Conditions) < 4 {
				t.Error("expected at least 4 conditions")
			}
		},
	},
	{
		name: "comparison_operators",
		yaml: `
title: Large File Transfer
status: test
level: medium
logsource:
    category: network_connection
    product: windows
detection:
    selection:
        BytesSent|gt: '10000000'
    condition: selection
`,
		validate: func(t *testing.T, r *ParseResult) {
			found := false
			for _, c := range r.Conditions {
				if c.Field == "BytesSent" && c.Operator == ">" {
					found = true
				}
			}
			if !found {
				t.Error("expected BytesSent > condition")
			}
		},
	},
	{
		name: "pipe_in_field_value",
		yaml: `
title: LOLBIN with Pipe
status: test
level: medium
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        CommandLine|contains: 'cmd.exe /c echo |'
    condition: selection
`,
		validate: func(t *testing.T, r *ParseResult) {
			if len(r.Conditions) == 0 {
				t.Error("expected conditions")
			}
		},
	},
	{
		name: "single_keyword_string",
		yaml: `
title: Keyword String
status: test
level: medium
logsource:
    category: process_creation
    product: windows
detection:
    keywords: 'mimikatz'
    condition: keywords
`,
		validate: func(t *testing.T, r *ParseResult) {
			found := false
			for _, c := range r.Conditions {
				if c.Operator == "keyword" && c.Value == "mimikatz" {
					found = true
				}
			}
			if !found {
				t.Error("expected keyword condition for mimikatz")
			}
		},
	},
	{
		name: "near_aggregation",
		yaml: `
title: Near Detection
status: test
level: high
logsource:
    product: windows
    service: security
detection:
    selection1:
        EventID: 4624
    selection2:
        EventID: 4672
    timeframe: 1m
    condition: selection1 | near selection1 and selection2
`,
		validate: func(t *testing.T, r *ParseResult) {
			if len(r.Commands) == 0 || r.Commands[0] != "near" {
				t.Errorf("expected near command, got %v", r.Commands)
			}
		},
	},
	{
		name: "empty_string_value",
		yaml: `
title: Empty String
status: test
level: low
logsource:
    category: test
detection:
    selection:
        FieldName: ''
    condition: selection
`,
		validate: func(t *testing.T, r *ParseResult) {
			found := false
			for _, c := range r.Conditions {
				if c.Field == "FieldName" && c.Value == "" {
					found = true
				}
			}
			if !found {
				t.Error("expected empty string condition")
			}
		},
	},
	{
		name: "float_event_id",
		yaml: `
title: Float Value
status: test
level: medium
logsource:
    product: windows
detection:
    selection:
        Score: 9.5
    condition: selection
`,
		validate: func(t *testing.T, r *ParseResult) {
			found := false
			for _, c := range r.Conditions {
				if c.Field == "Score" {
					found = true
				}
			}
			if !found {
				t.Error("expected Score condition")
			}
		},
	},
	{
		name: "wildcard_star_exists",
		yaml: `
title: Field Exists
status: test
level: low
logsource:
    category: test
detection:
    selection:
        FieldName: '*'
    condition: selection
`,
		validate: func(t *testing.T, r *ParseResult) {
			found := false
			for _, c := range r.Conditions {
				if c.Field == "FieldName" && c.Operator == "exists" && c.Value == "true" {
					found = true
				}
			}
			if !found {
				t.Error("expected FieldName exists=true")
				for _, c := range r.Conditions {
					t.Logf("  %+v", c)
				}
			}
		},
	},
	{
		name: "gcp_audit_log",
		yaml: `
title: GCP Service Account Key Creation
status: test
level: medium
logsource:
    product: gcp
    service: gcp.audit
detection:
    selection:
        methodName:
            - 'google.iam.admin.v1.CreateServiceAccountKey'
            - 'google.iam.admin.v1.UploadServiceAccountKey'
    condition: selection
`,
		validate: func(t *testing.T, r *ParseResult) {
			if r.LogSource.Product != "gcp" {
				t.Error("expected gcp product")
			}
		},
	},
	{
		name: "azure_ad_mfa_disabled",
		yaml: `
title: Azure AD MFA Disabled
status: test
level: high
logsource:
    product: azure
    service: auditlogs
detection:
    selection:
        operationName: 'Disable Strong Authentication'
        result: 'success'
    condition: selection
`,
		validate: func(t *testing.T, r *ParseResult) {
			if r.LogSource.Service != "auditlogs" {
				t.Errorf("expected service auditlogs, got %q", r.LogSource.Service)
			}
		},
	},

	// ====================================================================
	// Aggregation-heavy rules
	// ====================================================================
	{
		name: "agg_count_by_single_field",
		yaml: `
title: Brute Force Login Attempts
status: test
level: medium
logsource:
    product: windows
    service: security
detection:
    selection:
        EventID: 4625
    timeframe: 5m
    condition: selection | count() by SourceIP > 10
`,
		validate: func(t *testing.T, r *ParseResult) {
			if len(r.Commands) == 0 || r.Commands[0] != "count" {
				t.Errorf("expected count command, got %v", r.Commands)
			}
			if len(r.GroupByFields) != 1 || r.GroupByFields[0] != "SourceIP" {
				t.Errorf("expected groupBy [SourceIP], got %v", r.GroupByFields)
			}
			foundAgg := false
			for _, c := range r.Conditions {
				if c.Field == "count()" && c.Operator == ">" && c.Value == "10" {
					foundAgg = true
				}
			}
			if !foundAgg {
				t.Error("expected count() > 10 aggregation condition")
			}
		},
	},
	{
		name: "agg_count_with_field_arg",
		yaml: `
title: Excessive Failed Logins Per User
status: test
level: high
logsource:
    product: windows
    service: security
detection:
    selection:
        EventID: 4625
    timeframe: 10m
    condition: selection | count(TargetUserName) by SourceIP > 5
`,
		validate: func(t *testing.T, r *ParseResult) {
			foundAgg := false
			for _, c := range r.Conditions {
				if c.Field == "count(TargetUserName)" && c.Operator == ">" && c.Value == "5" {
					foundAgg = true
				}
			}
			if !foundAgg {
				t.Error("expected count(TargetUserName) > 5 condition")
			}
			if len(r.GroupByFields) != 1 || r.GroupByFields[0] != "SourceIP" {
				t.Errorf("expected groupBy [SourceIP], got %v", r.GroupByFields)
			}
		},
	},
	{
		name: "agg_sum_by_multiple_fields",
		yaml: `
title: Large Data Exfil
status: test
level: high
logsource:
    category: network_connection
    product: windows
detection:
    selection:
        Initiated: 'true'
    condition: selection | sum(BytesSent) by SourceIP, DestinationIP >= 100000000
`,
		validate: func(t *testing.T, r *ParseResult) {
			if len(r.Commands) != 1 || r.Commands[0] != "sum" {
				t.Errorf("expected [sum], got %v", r.Commands)
			}
			if len(r.GroupByFields) != 2 {
				t.Errorf("expected 2 groupBy fields, got %v", r.GroupByFields)
			}
			foundAgg := false
			for _, c := range r.Conditions {
				if c.Field == "sum(BytesSent)" && c.Operator == ">=" && c.Value == "100000000" {
					foundAgg = true
				}
			}
			if !foundAgg {
				t.Error("expected sum(BytesSent) >= 100000000")
			}
		},
	},
	{
		name: "agg_avg",
		yaml: `
title: High Average Payload Size
status: test
level: medium
logsource:
    category: network_connection
detection:
    selection:
        DestinationPort: 443
    condition: selection | avg(PayloadSize) by SourceIP > 5000
`,
		validate: func(t *testing.T, r *ParseResult) {
			if len(r.Commands) != 1 || r.Commands[0] != "avg" {
				t.Errorf("expected [avg], got %v", r.Commands)
			}
			foundAgg := false
			for _, c := range r.Conditions {
				if c.Field == "avg(PayloadSize)" && c.Operator == ">" {
					foundAgg = true
				}
			}
			if !foundAgg {
				t.Error("expected avg(PayloadSize) > condition")
			}
		},
	},
	{
		name: "agg_min",
		yaml: `
title: Abnormally Low Response Time
status: test
level: low
logsource:
    category: proxy
detection:
    selection:
        cs-method: GET
    condition: selection | min(time-taken) by cs-host < 1
`,
		validate: func(t *testing.T, r *ParseResult) {
			if len(r.Commands) != 1 || r.Commands[0] != "min" {
				t.Errorf("expected [min], got %v", r.Commands)
			}
		},
	},
	{
		name: "agg_max",
		yaml: `
title: Abnormally High Response Size
status: test
level: medium
logsource:
    category: proxy
detection:
    selection:
        cs-method: POST
    condition: selection | max(sc-bytes) by cs-host > 50000000
`,
		validate: func(t *testing.T, r *ParseResult) {
			if len(r.Commands) != 1 || r.Commands[0] != "max" {
				t.Errorf("expected [max], got %v", r.Commands)
			}
		},
	},
	{
		name: "agg_count_eq",
		yaml: `
title: Exactly One Login
status: test
level: low
logsource:
    product: windows
    service: security
detection:
    selection:
        EventID: 4624
    condition: selection | count() by TargetUserName = 1
`,
		validate: func(t *testing.T, r *ParseResult) {
			foundAgg := false
			for _, c := range r.Conditions {
				if c.Field == "count()" && c.Operator == "=" && c.Value == "1" {
					foundAgg = true
				}
			}
			if !foundAgg {
				t.Error("expected count() = 1")
			}
		},
	},
	{
		name: "agg_count_lte",
		yaml: `
title: Few Events
status: test
level: low
logsource:
    product: windows
detection:
    selection:
        EventID: 1
    condition: selection | count() <= 3
`,
		validate: func(t *testing.T, r *ParseResult) {
			foundAgg := false
			for _, c := range r.Conditions {
				if c.Field == "count()" && c.Operator == "<=" && c.Value == "3" {
					foundAgg = true
				}
			}
			if !foundAgg {
				t.Error("expected count() <= 3")
			}
		},
	},
	{
		name: "agg_count_lt",
		yaml: `
title: Under Threshold
status: test
level: low
logsource:
    product: windows
detection:
    selection:
        EventID: 1
    condition: selection | count() < 5
`,
		validate: func(t *testing.T, r *ParseResult) {
			foundAgg := false
			for _, c := range r.Conditions {
				if c.Field == "count()" && c.Operator == "<" && c.Value == "5" {
					foundAgg = true
				}
			}
			if !foundAgg {
				t.Error("expected count() < 5")
			}
		},
	},
	{
		name: "agg_near_three_items",
		yaml: `
title: Near Three Events
status: test
level: high
logsource:
    product: windows
    service: security
detection:
    login:
        EventID: 4624
    priv:
        EventID: 4672
    process:
        EventID: 4688
    timeframe: 2m
    condition: login | near login and priv and process
`,
		validate: func(t *testing.T, r *ParseResult) {
			if len(r.Commands) != 1 || r.Commands[0] != "near" {
				t.Errorf("expected [near], got %v", r.Commands)
			}
		},
	},
	{
		name: "agg_with_complex_selection",
		yaml: `
title: Password Spray
status: test
level: high
logsource:
    product: windows
    service: security
detection:
    selection:
        EventID: 4625
        Status: '0xC000006D'
    filter:
        TargetUserName|endswith: '$'
    timeframe: 10m
    condition: selection and not filter | count(TargetUserName) by IpAddress > 20
`,
		validate: func(t *testing.T, r *ParseResult) {
			if len(r.Commands) == 0 || r.Commands[0] != "count" {
				t.Errorf("expected count command, got %v", r.Commands)
			}
			foundEventID := false
			for _, c := range r.Conditions {
				if c.Field == "EventID" && c.Value == "4625" {
					foundEventID = true
				}
			}
			if !foundEventID {
				t.Error("expected EventID=4625 from selection")
			}
		},
	},

	// ====================================================================
	// Complex real-world rules with advanced features
	// ====================================================================
	{
		name: "sysmon_process_injection",
		yaml: `
title: Process Injection Detected via CreateRemoteThread
status: test
level: high
logsource:
    category: create_remote_thread
    product: windows
detection:
    selection:
        SourceImage|endswith:
            - '\rundll32.exe'
            - '\powershell.exe'
            - '\pwsh.exe'
            - '\mshta.exe'
            - '\wscript.exe'
            - '\cscript.exe'
    filter_target:
        TargetImage|endswith:
            - '\svchost.exe'
            - '\csrss.exe'
            - '\lsass.exe'
    condition: selection and filter_target
tags:
    - attack.defense_evasion
    - attack.privilege_escalation
    - attack.t1055.003
`,
		validate: func(t *testing.T, r *ParseResult) {
			if len(r.Tags) != 3 {
				t.Errorf("expected 3 tags, got %d", len(r.Tags))
			}
			sourceCount := 0
			targetCount := 0
			for _, c := range r.Conditions {
				if c.Field == "SourceImage" {
					sourceCount++
				}
				if c.Field == "TargetImage" {
					targetCount++
				}
			}
			if sourceCount == 0 {
				t.Error("expected SourceImage conditions")
			}
			if targetCount == 0 {
				t.Error("expected TargetImage conditions")
			}
		},
	},
	{
		name: "credential_dumping_lsass_access",
		yaml: `
title: LSASS Memory Access
status: stable
level: critical
logsource:
    category: process_access
    product: windows
detection:
    selection:
        TargetImage|endswith: '\lsass.exe'
        GrantedAccess|contains:
            - '0x1010'
            - '0x1038'
            - '0x1fffff'
            - '0x01000'
    filter_legitimate:
        SourceImage|startswith:
            - 'C:\Windows\System32\'
            - 'C:\Program Files\Windows Defender\'
            - 'C:\Program Files\VMware\'
    filter_csrss:
        SourceImage|endswith: '\csrss.exe'
    condition: selection and not filter_legitimate and not filter_csrss
`,
		validate: func(t *testing.T, r *ParseResult) {
			negatedCount := 0
			for _, c := range r.Conditions {
				if c.Negated {
					negatedCount++
				}
			}
			if negatedCount < 2 {
				t.Errorf("expected at least 2 negated conditions (two filters), got %d", negatedCount)
			}
		},
	},
	{
		name: "scheduled_task_lateral_movement",
		yaml: `
title: Scheduled Task Created For Lateral Movement
status: test
level: high
logsource:
    product: windows
    service: security
detection:
    selection:
        EventID: 4698
    task_contains:
        TaskContent|contains|all:
            - '<Exec>'
            - '<Command>'
    task_suspicious:
        TaskContent|contains:
            - 'powershell'
            - 'cmd.exe /c'
            - 'mshta'
            - 'rundll32'
            - 'regsvr32'
            - 'wscript'
            - 'cscript'
    condition: selection and task_contains and task_suspicious
`,
		validate: func(t *testing.T, r *ParseResult) {
			foundAll := false
			foundOR := false
			for _, c := range r.Conditions {
				if c.Field == "TaskContent" && c.Operator == "contains" && len(c.Alternatives) == 0 {
					foundAll = true
				}
				if c.Field == "TaskContent" && c.Operator == "contains" && len(c.Alternatives) > 1 {
					foundOR = true
				}
			}
			if !foundAll {
				t.Error("expected AND'd TaskContent conditions from |all")
			}
			if !foundOR {
				t.Error("expected OR'd TaskContent alternatives from task_suspicious")
			}
		},
	},
	{
		name: "windows_service_install_suspicious",
		yaml: `
title: Suspicious Service Installation
status: test
level: high
logsource:
    product: windows
    service: system
detection:
    selection:
        EventID: 7045
    suspicious_type:
        ServiceType: 'kernel mode driver'
    suspicious_path:
        ImagePath|contains:
            - '\AppData\'
            - '\Temp\'
            - '\Desktop\'
            - '\Downloads\'
            - 'C:\Users\Public\'
    suspicious_name:
        ServiceName|re: '^[a-zA-Z]{8,}$'
    condition: selection and (suspicious_type or suspicious_path or suspicious_name)
`,
		validate: func(t *testing.T, r *ParseResult) {
			foundEventID := false
			foundRegex := false
			for _, c := range r.Conditions {
				if c.Field == "EventID" && c.Value == "7045" {
					foundEventID = true
				}
				if c.Operator == "matches" {
					foundRegex = true
				}
			}
			if !foundEventID {
				t.Error("expected EventID=7045")
			}
			if !foundRegex {
				t.Error("expected regex/matches for ServiceName")
			}
		},
	},
	{
		name: "kerberoasting_detection",
		yaml: `
title: Kerberoasting Activity
status: test
level: high
logsource:
    product: windows
    service: security
detection:
    selection:
        EventID: 4769
        TicketOptions: '0x40810000'
        TicketEncryptionType:
            - '0x17'
            - '0x18'
    filter_machine:
        ServiceName|endswith: '$'
    filter_service:
        ServiceName:
            - 'krbtgt'
            - 'kadmin'
    condition: selection and not filter_machine and not filter_service
`,
		validate: func(t *testing.T, r *ParseResult) {
			foundTicketEnc := false
			for _, c := range r.Conditions {
				if c.Field == "TicketEncryptionType" && len(c.Alternatives) > 0 {
					foundTicketEnc = true
				}
			}
			if !foundTicketEnc {
				t.Error("expected TicketEncryptionType with alternatives")
			}
		},
	},
	{
		name: "dcsync_detection",
		yaml: `
title: DCSync Attack
status: stable
level: critical
logsource:
    product: windows
    service: security
detection:
    selection:
        EventID: 4662
        Properties|contains:
            - '1131f6aa-9c07-11d1-f79f-00c04fc2dcd2'
            - '1131f6ad-9c07-11d1-f79f-00c04fc2dcd2'
            - '9923a32a-3607-11d2-b9be-0000f87a36b2'
            - '89e95b76-444d-4c62-991a-0facbeda640c'
    filter_accounts:
        SubjectUserName|endswith: '$'
    filter_system:
        SubjectUserSid:
            - 'S-1-5-18'
            - 'S-1-5-19'
            - 'S-1-5-20'
    condition: selection and not filter_accounts and not filter_system
`,
		validate: func(t *testing.T, r *ParseResult) {
			foundProps := false
			for _, c := range r.Conditions {
				if c.Field == "Properties" && len(c.Alternatives) >= 4 {
					foundProps = true
				}
			}
			if !foundProps {
				t.Error("expected Properties with 4+ alternatives")
			}
		},
	},
	{
		name: "pass_the_hash",
		yaml: `
title: Pass-the-Hash Activity
status: test
level: high
logsource:
    product: windows
    service: security
detection:
    selection:
        EventID: 4624
        LogonType: 9
        LogonProcessName: 'seclogo'
        AuthenticationPackageName: 'Negotiate'
    filter_system:
        TargetUserName: 'ANONYMOUS LOGON'
    filter_machine:
        TargetUserName|endswith: '$'
    condition: selection and not filter_system and not filter_machine
`,
		validate: func(t *testing.T, r *ParseResult) {
			if len(r.Conditions) < 4 {
				t.Errorf("expected at least 4 conditions, got %d", len(r.Conditions))
			}
		},
	},
	{
		name: "linux_reverse_shell",
		yaml: `
title: Linux Reverse Shell
status: test
level: critical
logsource:
    category: process_creation
    product: linux
detection:
    selection_bash:
        Image|endswith: '/bash'
        CommandLine|contains|all:
            - '-i'
            - '/dev/tcp/'
    selection_nc:
        Image|endswith:
            - '/nc'
            - '/ncat'
            - '/netcat'
        CommandLine|contains:
            - '-e /bin/sh'
            - '-e /bin/bash'
    selection_python:
        CommandLine|contains|all:
            - 'python'
            - 'socket'
            - 'subprocess'
    condition: selection_bash or selection_nc or selection_python
`,
		validate: func(t *testing.T, r *ParseResult) {
			if r.LogSource.Product != "linux" {
				t.Error("expected linux product")
			}
			if len(r.Conditions) < 3 {
				t.Error("expected at least 3 conditions")
			}
		},
	},
	{
		name: "kubernetes_pod_exec",
		yaml: `
title: Kubernetes Pod Exec
status: test
level: medium
logsource:
    product: kubernetes
    service: audit
detection:
    selection:
        verb: 'create'
        objectRef.resource: 'pods'
        objectRef.subresource: 'exec'
    filter_system:
        user.username|startswith:
            - 'system:serviceaccount:kube-system:'
            - 'system:serviceaccount:monitoring:'
    condition: selection and not filter_system
`,
		validate: func(t *testing.T, r *ParseResult) {
			if r.LogSource.Product != "kubernetes" {
				t.Error("expected kubernetes product")
			}
			foundSubresource := false
			for _, c := range r.Conditions {
				if c.Field == "objectRef.subresource" && c.Value == "exec" {
					foundSubresource = true
				}
			}
			if !foundSubresource {
				t.Error("expected objectRef.subresource=exec")
			}
		},
	},
	{
		name: "o365_mailbox_forwarding",
		yaml: `
title: Office 365 Mailbox Forwarding Rule
status: test
level: medium
logsource:
    product: m365
    service: exchange
detection:
    selection:
        Operation:
            - 'New-InboxRule'
            - 'Set-InboxRule'
        Parameters.Name:
            - 'ForwardTo'
            - 'ForwardAsAttachmentTo'
            - 'RedirectTo'
    condition: selection
`,
		validate: func(t *testing.T, r *ParseResult) {
			foundParam := false
			for _, c := range r.Conditions {
				if c.Field == "Parameters.Name" && len(c.Alternatives) == 3 {
					foundParam = true
				}
			}
			if !foundParam {
				t.Error("expected Parameters.Name with 3 alternatives")
			}
		},
	},
	{
		name: "aws_iam_policy_change",
		yaml: `
title: AWS IAM Policy Modification
status: test
level: medium
logsource:
    product: aws
    service: cloudtrail
detection:
    selection:
        eventSource: 'iam.amazonaws.com'
        eventName:
            - 'AttachGroupPolicy'
            - 'AttachRolePolicy'
            - 'AttachUserPolicy'
            - 'CreatePolicy'
            - 'CreatePolicyVersion'
            - 'DeleteGroupPolicy'
            - 'DeletePolicy'
            - 'DeletePolicyVersion'
            - 'DeleteRolePolicy'
            - 'DeleteUserPolicy'
            - 'DetachGroupPolicy'
            - 'DetachRolePolicy'
            - 'DetachUserPolicy'
            - 'PutGroupPolicy'
            - 'PutRolePolicy'
            - 'PutUserPolicy'
    condition: selection
`,
		validate: func(t *testing.T, r *ParseResult) {
			foundEventNames := false
			for _, c := range r.Conditions {
				if c.Field == "eventName" && len(c.Alternatives) == 16 {
					foundEventNames = true
				}
			}
			if !foundEventNames {
				t.Error("expected eventName with 16 alternatives")
			}
		},
	},
	{
		name: "base64_encoded_command",
		yaml: `
title: Base64 Encoded PowerShell
status: test
level: medium
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        CommandLine|base64offset|contains:
            - 'IEX'
            - 'Invoke-Expression'
    condition: selection
`,
		validate: func(t *testing.T, r *ParseResult) {
			found := false
			for _, c := range r.Conditions {
				if c.Field == "CommandLine" && c.Operator == "contains" {
					found = true
				}
			}
			if !found {
				t.Error("expected CommandLine contains condition with base64 variants")
			}
		},
	},
	{
		name: "wide_string_detection",
		yaml: `
title: Wide String Detection
status: test
level: medium
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        CommandLine|wide|contains: 'mimikatz'
    condition: selection
`,
		validate: func(t *testing.T, r *ParseResult) {
			found := false
			for _, c := range r.Conditions {
				if c.Field == "CommandLine" && c.Operator == "contains" {
					found = true
				}
			}
			if !found {
				t.Error("expected CommandLine contains condition")
			}
		},
	},
	{
		name: "complex_three_level_nesting",
		yaml: `
title: Three Level Deep Nesting
status: test
level: high
logsource:
    category: process_creation
    product: windows
detection:
    parent_selection:
        ParentImage|endswith:
            - '\explorer.exe'
            - '\cmd.exe'
    process_selection:
        Image|endswith:
            - '\rundll32.exe'
            - '\regsvr32.exe'
    cmdline_1:
        CommandLine|contains: 'javascript:'
    cmdline_2:
        CommandLine|contains: 'vbscript:'
    filter_legit:
        CommandLine|contains: 'shell32.dll'
    condition: parent_selection and process_selection and (cmdline_1 or cmdline_2) and not filter_legit
`,
		validate: func(t *testing.T, r *ParseResult) {
			if len(r.Conditions) < 4 {
				t.Errorf("expected at least 4 conditions, got %d", len(r.Conditions))
			}
			foundNegated := false
			for _, c := range r.Conditions {
				if c.Field == "CommandLine" && c.Negated && c.Value == "shell32.dll" {
					foundNegated = true
				}
			}
			if !foundNegated {
				t.Error("expected negated shell32.dll condition")
			}
		},
	},
	{
		name: "exists_false_modifier",
		yaml: `
title: Field Does Not Exist
status: test
level: low
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        Image|endswith: '\cmd.exe'
    filter:
        ParentImage|exists: false
    condition: selection and not filter
`,
		validate: func(t *testing.T, r *ParseResult) {
			foundExists := false
			for _, c := range r.Conditions {
				if c.Field == "ParentImage" && c.Operator == "exists" && c.Value == "false" {
					foundExists = true
				}
			}
			if !foundExists {
				t.Error("expected ParentImage exists=false")
			}
		},
	},
	{
		name: "multiple_logsource_fields",
		yaml: `
title: Full LogSource
status: test
level: medium
logsource:
    category: process_creation
    product: windows
    service: sysmon
detection:
    selection:
        Image|endswith: '\test.exe'
    condition: selection
`,
		validate: func(t *testing.T, r *ParseResult) {
			if r.LogSource == nil {
				t.Fatal("expected logsource")
			}
			if r.LogSource.Category != "process_creation" {
				t.Errorf("expected category process_creation, got %q", r.LogSource.Category)
			}
			if r.LogSource.Product != "windows" {
				t.Errorf("expected product windows, got %q", r.LogSource.Product)
			}
			if r.LogSource.Service != "sysmon" {
				t.Errorf("expected service sysmon, got %q", r.LogSource.Service)
			}
		},
	},
	{
		name: "gt_gte_comparison_mix",
		yaml: `
title: Comparison Operators Mix
status: test
level: medium
logsource:
    product: windows
detection:
    sel_gt:
        EventID|gt: '1000'
    sel_gte:
        ProcessId|gte: '500'
    sel_lt:
        ThreadId|lt: '100'
    sel_lte:
        Duration|lte: '50'
    condition: sel_gt and sel_gte and sel_lt and sel_lte
`,
		validate: func(t *testing.T, r *ParseResult) {
			ops := make(map[string]bool)
			for _, c := range r.Conditions {
				ops[c.Operator] = true
			}
			for _, expected := range []string{">", ">=", "<", "<="} {
				if !ops[expected] {
					t.Errorf("expected operator %q", expected)
				}
			}
		},
	},
	{
		name: "cidr_multiple_ranges",
		yaml: `
title: Internal CIDR Ranges
status: test
level: low
logsource:
    category: network_connection
detection:
    selection:
        DestinationIp|cidr:
            - '10.0.0.0/8'
            - '172.16.0.0/12'
            - '192.168.0.0/16'
            - '100.64.0.0/10'
    condition: selection
`,
		validate: func(t *testing.T, r *ParseResult) {
			found := false
			for _, c := range r.Conditions {
				if c.Field == "DestinationIp" && c.Operator == "cidrmatch" && len(c.Alternatives) == 4 {
					found = true
				}
			}
			if !found {
				t.Error("expected DestinationIp cidrmatch with 4 alternatives")
			}
		},
	},
	{
		name: "many_detection_blocks_all_of_selection",
		yaml: `
title: All of Selection Pattern
status: test
level: high
logsource:
    category: process_creation
    product: windows
detection:
    selection_parent:
        ParentImage|endswith: '\winword.exe'
    selection_child:
        Image|endswith: '\cmd.exe'
    selection_cmd:
        CommandLine|contains: '/c'
    selection_encoded:
        CommandLine|contains: '-enc'
    condition: all of selection_*
`,
		validate: func(t *testing.T, r *ParseResult) {
			if len(r.Conditions) < 4 {
				t.Errorf("expected at least 4 conditions from all of selection_*, got %d", len(r.Conditions))
			}
		},
	},
	{
		name: "status_experimental",
		yaml: `
title: Experimental Rule
status: experimental
level: informational
logsource:
    category: test
detection:
    selection:
        field: value
    condition: selection
`,
		validate: func(t *testing.T, r *ParseResult) {
			if r.Status != "experimental" {
				t.Errorf("expected status experimental, got %q", r.Status)
			}
			if r.Level != "informational" {
				t.Errorf("expected level informational, got %q", r.Level)
			}
		},
	},
}

func TestRealWorldRules(t *testing.T) {
	for _, tt := range realWorldRules {
		t.Run(tt.name, func(t *testing.T) {
			result := ExtractConditions(tt.yaml)
			if tt.wantErr {
				if len(result.Errors) == 0 {
					t.Error("expected errors")
				}
				return
			}
			if len(result.Errors) > 0 {
				t.Errorf("unexpected errors: %v", result.Errors)
			}
			if tt.validate != nil {
				tt.validate(t, result)
			}
		})
	}
}
