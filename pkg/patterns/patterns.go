package patterns

import "regexp"

// Severity levels for findings
type Severity string

const (
	SeverityCritical Severity = "CRITICAL"
	SeverityHigh     Severity = "HIGH"
	SeverityMedium   Severity = "MEDIUM"
	SeverityLow      Severity = "LOW"
	SeverityInfo     Severity = "INFO"
)

// Pattern defines a secret detection rule
type Pattern struct {
	Name         string
	Regex        *regexp.Regexp
	Severity     Severity
	Description  string
	ContextRegex *regexp.Regexp // must match the line for the finding to be reported
	EntropyCheck bool           // if true, apply Shannon entropy gate
	MinEntropy   float64        // minimum entropy required (only used if EntropyCheck=true)
}

// Compiled patterns for secret detection
var Patterns []*Pattern

func init() {
	raw := []struct {
		name         string
		pattern      string
		context      string
		severity     Severity
		description  string
		entropyCheck bool
		minEntropy   float64
	}{
		// ─── Cloud Providers ──────────────────────────────────────────────────────────
		{
			// Covers AKIA (long-term), ASIA (session), ABIA (STS), ACCA (AWS China), A3T*
			name:        "AWS Access Key ID",
			pattern:     `\b((?:A3T[A-Z0-9]|AKIA|ASIA|ABIA|ACCA|AGPA|AIDA|AROA|AIPA|ANPA|ANVA)[A-Z2-7]{16})\b`,
			severity:    SeverityCritical,
			description: "AWS Access Key ID",
		},
		{
			name:        "AWS Secret Access Key",
			pattern:     `(?i)aws.{0,20}(?:secret|key).{0,10}[=:]\s*['"]?([A-Za-z0-9/+]{40})['"]?`,
			severity:    SeverityCritical,
			description: "AWS Secret Access Key",
		},
		{
			name:        "AWS MWS Key",
			pattern:     `amzn\.mws\.[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}`,
			severity:    SeverityHigh,
			description: "Amazon MWS Auth Token",
		},
		{
			name:        "Google API Key",
			pattern:     `\b(AIza[\w-]{35})(?:[\x60'"\s;]|\\[nr]|$)`,
			severity:    SeverityHigh,
			description: "Google API Key",
		},
		{
			name:        "Google OAuth Token",
			pattern:     `ya29\.[0-9A-Za-z\-_]+`,
			severity:    SeverityHigh,
			description: "Google OAuth Access Token",
		},
		{
			name:        "Google Cloud Service Account",
			pattern:     `(?i)"type"\s*:\s*"service_account"`,
			severity:    SeverityHigh,
			description: "Google Cloud Service Account JSON",
		},
		{
			name:        "Firebase API Key",
			pattern:     `(?i)firebase[^'"]{0,20}['"][A-Za-z0-9\-_]{30,50}['"]`,
			severity:    SeverityHigh,
			description: "Firebase API Key",
		},
		{
			name:        "Azure Storage Key",
			pattern:     `(?i)DefaultEndpointsProtocol=https?;AccountName=[^;]+;AccountKey=[A-Za-z0-9+/=]{88}`,
			severity:    SeverityCritical,
			description: "Azure Storage Connection String",
		},
		{
			name:        "Azure SAS Token",
			pattern:     `(?i)sv=\d{4}-\d{2}-\d{2}&s[a-z]=&[a-z]{2}=.{10,}&sig=[A-Za-z0-9%+/=]{43,}`,
			severity:    SeverityHigh,
			description: "Azure SAS Token",
		},
		{
			// Azure AD client secret — 3 alphanum chars + digit + Q~ prefix (gitleaks pattern)
			name:        "Azure AD Client Secret",
			pattern:     `(?:^|[\\'"\x60\s>=:(,)])([a-zA-Z0-9_~.]{3}\dQ~[a-zA-Z0-9_~.-]{31,34})(?:$|[\\'"\x60\s<),])`,
			severity:    SeverityCritical,
			description: "Azure AD Client Secret",
		},
		{
			name:        "Cloudflare API Token",
			pattern:     `(?i)[\w.-]{0,50}?(?:cloudflare)(?:[ \t\w.-]{0,20})[\s'"]{0,3}(?:=|>|:{1,3}=|\|\||:|=>|\?=|,)[\x60'"\s=]{0,5}([a-z0-9_-]{40})(?:[\x60'"\s;]|\\[nr]|$)`,
			severity:    SeverityHigh,
			description: "Cloudflare API Token",
		},
		{
			name:        "Cloudflare Global API Key",
			pattern:     `(?i)[\w.-]{0,50}?(?:cloudflare)(?:[ \t\w.-]{0,20})[\s'"]{0,3}(?:=|>|:{1,3}=|\|\||:|=>|\?=|,)[\x60'"\s=]{0,5}([a-f0-9]{37})(?:[\x60'"\s;]|\\[nr]|$)`,
			severity:    SeverityCritical,
			description: "Cloudflare Global API Key",
		},
		{
			name:        "DigitalOcean Personal Access Token",
			pattern:     `\b(dop_v1_[a-f0-9]{64})(?:[\x60'"\s;]|\\[nr]|$)`,
			severity:    SeverityHigh,
			description: "DigitalOcean Personal Access Token",
		},
		{
			name:        "DigitalOcean OAuth Token",
			pattern:     `\b(doo_v1_[a-f0-9]{64})(?:[\x60'"\s;]|\\[nr]|$)`,
			severity:    SeverityHigh,
			description: "DigitalOcean OAuth Token",
		},
		{
			name:        "DigitalOcean Refresh Token",
			pattern:     `\b(dor_v1_[a-f0-9]{64})(?:[\x60'"\s;]|\\[nr]|$)`,
			severity:    SeverityHigh,
			description: "DigitalOcean Refresh Token",
		},
		{
			name:        "Heroku API Key",
			pattern:     `(?i)heroku.{0,20}[0-9A-F]{8}-[0-9A-F]{4}-[0-9A-F]{4}-[0-9A-F]{4}-[0-9A-F]{12}`,
			severity:    SeverityHigh,
			description: "Heroku API Key",
		},

		// ─── AI / LLM Providers ───────────────────────────────────────────────────────
		{
			// Covers new sk-proj-*, sk-svcacct-*, sk-admin-* formats and legacy sk-<20>T3BlbkFJ<20>
			name:        "OpenAI API Key",
			pattern:     `\b(sk-(?:proj|svcacct|admin)-[A-Za-z0-9_-]{58,74}T3BlbkFJ[A-Za-z0-9_-]{58,74}|sk-[a-zA-Z0-9]{20}T3BlbkFJ[a-zA-Z0-9]{20})\b`,
			severity:    SeverityCritical,
			description: "OpenAI API Key",
		},
		{
			name:        "Anthropic API Key",
			pattern:     `\b(sk-ant-api03-[a-zA-Z0-9_\-]{93}AA)(?:[\x60'"\s;]|\\[nr]|$)`,
			severity:    SeverityCritical,
			description: "Anthropic API Key",
		},
		{
			name:        "Anthropic Admin Key",
			pattern:     `\b(sk-ant-admin01-[a-zA-Z0-9_\-]{93}AA)(?:[\x60'"\s;]|\\[nr]|$)`,
			severity:    SeverityCritical,
			description: "Anthropic Admin API Key",
		},
		{
			name:        "HuggingFace Access Token",
			pattern:     `\b(hf_(?i:[a-z]{34}))(?:[\x60'"\s;]|\\[nr]|$)`,
			severity:    SeverityHigh,
			description: "HuggingFace Access Token",
		},

		// ─── Version Control & CI/CD ──────────────────────────────────────────────────
		{
			name:        "GitHub Personal Access Token (Classic)",
			pattern:     `ghp_[A-Za-z0-9]{36}`,
			severity:    SeverityCritical,
			description: "GitHub Personal Access Token (classic)",
		},
		{
			// Fine-grained PAT — longer fixed format
			name:        "GitHub Fine-Grained PAT",
			pattern:     `github_pat_\w{82}`,
			severity:    SeverityCritical,
			description: "GitHub Fine-Grained Personal Access Token",
		},
		{
			name:        "GitHub OAuth Token",
			pattern:     `gho_[A-Za-z0-9]{36}`,
			severity:    SeverityCritical,
			description: "GitHub OAuth Access Token",
		},
		{
			name:        "GitHub App Token",
			pattern:     `(ghu|ghs)_[A-Za-z0-9]{36}`,
			severity:    SeverityCritical,
			description: "GitHub App Token (user/server)",
		},
		{
			name:        "GitHub Refresh Token",
			pattern:     `ghr_[A-Za-z0-9]{76}`,
			severity:    SeverityCritical,
			description: "GitHub Refresh Token",
		},
		{
			name:        "GitLab Personal Access Token",
			pattern:     `glpat-[\w-]{20}`,
			severity:    SeverityCritical,
			description: "GitLab Personal Access Token",
		},
		{
			name:        "GitLab CI/CD Job Token",
			pattern:     `glcbt-[0-9a-zA-Z]{1,5}_[0-9a-zA-Z_-]{20}`,
			severity:    SeverityHigh,
			description: "GitLab CI/CD Job Token",
		},
		{
			name:        "GitLab Deploy Token",
			pattern:     `gldt-[0-9a-zA-Z_\-]{20}`,
			severity:    SeverityHigh,
			description: "GitLab Deploy Token",
		},
		{
			name:        "GitLab Runner Token",
			pattern:     `glrt-[0-9a-zA-Z_\-]{20}`,
			severity:    SeverityHigh,
			description: "GitLab Runner Authentication Token",
		},
		{
			name:        "GitLab Pipeline Trigger Token",
			pattern:     `glptt-[0-9a-f]{40}`,
			severity:    SeverityHigh,
			description: "GitLab Pipeline Trigger Token",
		},
		{
			name:        "GitLab OAuth App Secret",
			pattern:     `gloas-[0-9a-zA-Z_\-]{64}`,
			severity:    SeverityCritical,
			description: "GitLab OAuth App Secret",
		},
		{
			name:        "GitLab Agent Token",
			pattern:     `glagent-[0-9a-zA-Z_\-]{50}`,
			severity:    SeverityHigh,
			description: "GitLab Kubernetes Agent Token",
		},
		{
			name:        "GitLab Runner Registration Token",
			pattern:     `GR1348941[\w-]{20}`,
			severity:    SeverityHigh,
			description: "GitLab Runner Registration Token",
		},
		{
			name:        "CircleCI Token",
			pattern:     `(?i)circleci.{0,20}[=:]\s*['"]?([a-f0-9]{40})['"]?`,
			severity:    SeverityHigh,
			description: "CircleCI API Token",
		},
		{
			name:        "Travis CI Token",
			pattern:     `(?i)travis.{0,20}[=:]\s*['"]?([a-zA-Z0-9_-]{22})['"]?`,
			severity:    SeverityHigh,
			description: "Travis CI Token",
		},
		{
			name:        "Jenkins API Token",
			pattern:     `(?i)jenkins.{0,20}[=:]\s*['"]?([a-f0-9]{34})['"]?`,
			severity:    SeverityHigh,
			description: "Jenkins API Token",
		},

		// ─── Communication & Messaging ────────────────────────────────────────────────
		{
			// Specific Slack bot token format (more precise than generic xox)
			name:        "Slack Bot Token",
			pattern:     `xoxb-[0-9]{10,13}-[0-9]{10,13}[a-zA-Z0-9-]*`,
			severity:    SeverityHigh,
			description: "Slack Bot Token",
		},
		{
			name:        "Slack App Token",
			pattern:     `(?i)xapp-\d-[A-Z0-9]+-\d+-[a-z0-9]+`,
			severity:    SeverityHigh,
			description: "Slack App Token",
		},
		{
			name:        "Slack User Token",
			pattern:     `xox[pe](?:-[0-9]{10,13}){3}-[a-zA-Z0-9-]{28,34}`,
			severity:    SeverityHigh,
			description: "Slack User Token",
		},
		{
			name:        "Slack Legacy Token",
			pattern:     `xox[os]-\d+-\d+-\d+-[a-fA-F\d]+`,
			severity:    SeverityMedium,
			description: "Slack Legacy Token",
		},
		{
			name:        "Slack Webhook URL",
			pattern:     `(?:https?://)?hooks\.slack\.com/(?:services|workflows|triggers)/[A-Za-z0-9+/]{43,56}`,
			severity:    SeverityHigh,
			description: "Slack Incoming Webhook URL",
		},
		{
			name:        "Discord Webhook",
			pattern:     `https://discord(?:app)?\.com/api/webhooks/[0-9]{17,20}/[A-Za-z0-9\-_]{68}`,
			severity:    SeverityMedium,
			description: "Discord Webhook URL",
		},
		{
			name:        "Discord Bot Token",
			pattern:     `(?i)discord.{0,20}[=:]\s*['"]?([A-Za-z0-9]{24}\.[A-Za-z0-9]{6}\.[A-Za-z0-9_\-]{27,38})['"]?`,
			severity:    SeverityHigh,
			description: "Discord Bot Token",
		},
		{
			// Require 'telegr' keyword context to avoid FPs from numeric:base64 patterns in minified JS
			name:        "Telegram Bot Token",
			pattern:     `[0-9]{5,16}:(?:A)[a-z0-9_\-]{34}`,
			context:     `(?i)telegr`,
			severity:    SeverityHigh,
			description: "Telegram Bot API Token",
		},
		{
			name:        "Twilio API Key",
			pattern:     `SK[0-9a-fA-F]{32}`,
			severity:    SeverityHigh,
			description: "Twilio API Key SID",
		},
		{
			name:         "Twilio Account SID",
			pattern:      `AC[a-zA-Z0-9_\-]{32}`,
			severity:     SeverityMedium,
			description:  "Twilio Account SID",
			entropyCheck: true,
			minEntropy:   3.2,
		},
		{
			name:        "SendGrid API Key",
			pattern:     `\b(SG\.(?i)[a-z0-9=_\-\.]{66})(?:[\x60'"\s;]|\\[nr]|$)`,
			severity:    SeverityHigh,
			description: "SendGrid API Key",
		},
		{
			name:        "Sendinblue (Brevo) API Key",
			pattern:     `\b(xkeysib-[a-f0-9]{64}-(?i)[a-z0-9]{16})(?:[\x60'"\s;]|\\[nr]|$)`,
			severity:    SeverityHigh,
			description: "Sendinblue/Brevo API Key",
		},
		{
			name:        "Mailgun API Key",
			pattern:     `(?i)[\w.-]{0,50}?(?:mailgun)(?:[ \t\w.-]{0,20})[\s'"]{0,3}(?:=|>|:{1,3}=|\|\||:|=>|\?=|,)[\x60'"\s=]{0,5}(key-[a-f0-9]{32})(?:[\x60'"\s;]|\\[nr]|$)`,
			severity:    SeverityHigh,
			description: "Mailgun API Key",
		},
		{
			name:        "Mailchimp API Key",
			pattern:     `(?i)[\w.-]{0,50}?(?:MailchimpSDK.initialize|mailchimp)(?:[ \t\w.-]{0,20})[\s'"]{0,3}(?:=|>|:{1,3}=|\|\||:|=>|\?=|,)[\x60'"\s=]{0,5}([a-f0-9]{32}-us\d{1,2})(?:[\x60'"\s;]|\\[nr]|$)`,
			severity:    SeverityHigh,
			description: "Mailchimp API Key",
		},
		{
			name:        "Microsoft Teams Webhook",
			pattern:     `https://[a-z0-9]+\.webhook\.office\.com/webhookb2/[a-z0-9]{8}-(?:[a-z0-9]{4}-){3}[a-z0-9]{12}@[a-z0-9]{8}-(?:[a-z0-9]{4}-){3}[a-z0-9]{12}/IncomingWebhook/[a-z0-9]{32}/[a-z0-9]{8}-(?:[a-z0-9]{4}-){3}[a-z0-9]{12}`,
			severity:    SeverityHigh,
			description: "Microsoft Teams Incoming Webhook",
		},

		// ─── Payment Processors ───────────────────────────────────────────────────────
		{
			name:        "Stripe Live Secret Key",
			pattern:     `sk_live_[0-9a-zA-Z]{24,99}`,
			severity:    SeverityCritical,
			description: "Stripe Live Secret Key",
		},
		{
			name:        "Stripe Live Publishable Key",
			pattern:     `pk_live_[0-9a-zA-Z]{24,99}`,
			severity:    SeverityHigh,
			description: "Stripe Live Publishable Key",
		},
		{
			name:        "Stripe Test Key",
			pattern:     `(?:sk|pk)_test_[0-9a-zA-Z]{24,99}`,
			severity:    SeverityLow,
			description: "Stripe Test Key",
		},
		{
			name:        "Stripe Restricted Key",
			pattern:     `rk_live_[0-9a-zA-Z]{24,99}`,
			severity:    SeverityCritical,
			description: "Stripe Restricted Live Key",
		},
		{
			name:        "PayPal Braintree Access Token",
			pattern:     `access_token\$production\$[0-9a-z]{16}\$[0-9a-f]{32}`,
			severity:    SeverityCritical,
			description: "PayPal Braintree Production Access Token",
		},
		{
			// Square: sq0atp- (old) and EAAA (new format)
			name:        "Square Access Token",
			pattern:     `\b((?:EAAA|sq0atp-)[\w-]{22,60})(?:[\x60'"\s;]|\\[nr]|$)`,
			severity:    SeverityCritical,
			description: "Square Access Token",
		},
		{
			name:        "Square OAuth Secret",
			pattern:     `sq0csp-[0-9A-Za-z\-_]{43}`,
			severity:    SeverityCritical,
			description: "Square OAuth Secret",
		},

		// ─── Social Media ─────────────────────────────────────────────────────────────
		{
			name:        "Facebook App Secret",
			pattern:     `(?i)[\w.-]{0,50}?(?:facebook)(?:[ \t\w.-]{0,20})[\s'"]{0,3}(?:=|>|:{1,3}=|\|\||:|=>|\?=|,)[\x60'"\s=]{0,5}([a-f0-9]{32})(?:[\x60'"\s;]|\\[nr]|$)`,
			severity:    SeverityHigh,
			description: "Facebook App Secret",
		},
		{
			// More precise Facebook access token (EAA prefix covers page + user tokens)
			name:        "Facebook Access Token",
			pattern:     `\b(EAA[MC](?i)[a-z0-9]{100,})(?:[\x60'"\s;]|\\[nr]|$)`,
			severity:    SeverityHigh,
			description: "Facebook Access Token",
		},
		{
			name:        "Twitter Bearer Token",
			pattern:     `AAAAAAAAAAAAAAAAAAAAAA[A-Za-z0-9%]{33,50}`,
			context:     `(?i)(?:bearer|authorization|twitter|twitter_token|api_token)`,
			severity:    SeverityHigh,
			description: "Twitter Bearer Token",
			entropyCheck: true,
			minEntropy:   3.5,
		},
		{
			name:         "Twitter API Key/Secret",
			pattern:      `(?i)twitter.{0,20}(?:api[_-]?key|api[_-]?secret|access[_-]?token).{0,10}[=:]\s*['"]?([A-Za-z0-9]{25,50})['"]?`,
			severity:     SeverityHigh,
			description:  "Twitter API Key or Secret",
			entropyCheck: true,
			minEntropy:   3.2,
		},
		{
			name:        "LinkedIn Secret Key",
			pattern:     `(?i)linkedin.{0,20}[=:]\s*['"]?([A-Za-z0-9]{12,})['"]?`,
			severity:    SeverityMedium,
			description: "LinkedIn API Secret",
		},

		// ─── Authentication & Tokens ──────────────────────────────────────────────────
		{
			// Improved JWT regex from gitleaks: requires ey prefix in both header and payload
			name:        "JSON Web Token",
			pattern:     `\b(ey[a-zA-Z0-9]{17,}\.ey[a-zA-Z0-9\/\\_-]{17,}\.(?:[a-zA-Z0-9\/\\_-]{10,}={0,2})?)(?:[\x60'"\s;]|\\[nr]|$)`,
			severity:    SeverityHigh,
			description: "JSON Web Token (JWT)",
		},
		{
			name:        "Basic Auth in URL",
			pattern:     `https?://[a-zA-Z0-9_\-]+:[a-zA-Z0-9_\-@!#$%^&*]+@[a-zA-Z0-9._\-]+`,
			severity:    SeverityHigh,
			description: "Credentials embedded in URL",
		},
		{
			name:        "Authorization Bearer Token",
			pattern:     `(?i)(?:authorization|bearer)[^'"]*['"][Bb]earer\s+([A-Za-z0-9\-_=]+\.[A-Za-z0-9\-_=]+\.?[A-Za-z0-9\-_.+/=]*)['"]`,
			severity:    SeverityHigh,
			description: "Bearer Token in Authorization header",
		},
		{
			name:        "OAuth2 Access Token (Generic)",
			pattern:     `(?i)access_token['"\s]*[=:]+['"\s]*([A-Za-z0-9\-_.~+/]{20,})`,
			severity:    SeverityHigh,
			description: "OAuth2 Access Token",
		},
		{
			name:        "Refresh Token (Generic)",
			pattern:     `(?i)refresh_token['"\s]*[=:]+['"\s]*([A-Za-z0-9\-_.~+/]{20,})`,
			severity:    SeverityMedium,
			description: "OAuth2 Refresh Token",
		},

		// ─── Private Keys & Certificates ─────────────────────────────────────────────
		{
			name:        "RSA Private Key",
			pattern:     `-----BEGIN RSA PRIVATE KEY-----`,
			severity:    SeverityCritical,
			description: "RSA Private Key",
		},
		{
			name:        "DSA Private Key",
			pattern:     `-----BEGIN DSA PRIVATE KEY-----`,
			severity:    SeverityCritical,
			description: "DSA Private Key",
		},
		{
			name:        "EC Private Key",
			pattern:     `-----BEGIN EC PRIVATE KEY-----`,
			severity:    SeverityCritical,
			description: "EC (Elliptic Curve) Private Key",
		},
		{
			name:        "OpenSSH Private Key",
			pattern:     `-----BEGIN OPENSSH PRIVATE KEY-----`,
			severity:    SeverityCritical,
			description: "OpenSSH Private Key",
		},
		{
			name:        "PGP Private Key",
			pattern:     `-----BEGIN PGP PRIVATE KEY BLOCK-----`,
			severity:    SeverityCritical,
			description: "PGP Private Key Block",
		},
		{
			name:        "Private Key Header (Generic)",
			pattern:     `-----BEGIN [A-Z ]{1,30}PRIVATE KEY(?:\s+BLOCK)?-----`,
			severity:    SeverityCritical,
			description: "Generic private key header",
		},

		// ─── Databases & Infrastructure ───────────────────────────────────────────────
		{
			name:        "Generic Database Connection String",
			pattern:     `(?i)(?:mongodb|postgres|postgresql|mysql|mssql|redis|amqp)://[a-zA-Z0-9_\-]+:[^@\s'"]{3,}@[a-zA-Z0-9._\-]+`,
			severity:    SeverityCritical,
			description: "Database Connection String with credentials",
		},
		{
			name:        "MongoDB Connection String",
			pattern:     `mongodb(?:\+srv)?://[^:]+:[^@]+@[^/]+`,
			severity:    SeverityCritical,
			description: "MongoDB Connection String",
		},
		{
			name:        "Redis Connection String",
			pattern:     `redis://:[^@]+@[a-zA-Z0-9._\-]+:[0-9]+`,
			severity:    SeverityHigh,
			description: "Redis Connection String with password",
		},
		{
			name:        "Databricks API Token",
			pattern:     `\b(dapi[a-f0-9]{32}(?:-\d)?)(?:[\x60'"\s;]|\\[nr]|$)`,
			severity:    SeverityHigh,
			description: "Databricks API Token",
		},
		{
			name:        "HashiCorp Vault Service Token",
			pattern:     `\b(hvs\.[\w-]{90,120})(?:[\x60'"\s;]|\\[nr]|$)`,
			severity:    SeverityCritical,
			description: "HashiCorp Vault Service Token",
		},
		{
			name:        "HashiCorp Vault Batch Token",
			pattern:     `\b(hvb\.[\w-]{138,300})(?:[\x60'"\s;]|\\[nr]|$)`,
			severity:    SeverityCritical,
			description: "HashiCorp Vault Batch Token",
		},
		{
			name:        "PlanetScale API Token",
			pattern:     `\b(pscale_tkn_(?i)[\w=.\-]{32,64})(?:[\x60'"\s;]|\\[nr]|$)`,
			severity:    SeverityHigh,
			description: "PlanetScale API Token",
		},
		{
			name:        "PlanetScale Password",
			pattern:     `\b(pscale_pw_(?i)[\w=.\-]{32,64})(?:[\x60'"\s;]|\\[nr]|$)`,
			severity:    SeverityCritical,
			description: "PlanetScale Database Password",
		},
		{
			name:        "PlanetScale OAuth Token",
			pattern:     `\b(pscale_oauth_[\w=.\-]{32,64})(?:[\x60'"\s;]|\\[nr]|$)`,
			severity:    SeverityHigh,
			description: "PlanetScale OAuth Token",
		},

		// ─── Third-Party Services ─────────────────────────────────────────────────────
		{
			name:        "Shopify Access Token",
			pattern:     `shpat_[a-fA-F0-9]{32}`,
			severity:    SeverityCritical,
			description: "Shopify Access Token",
		},
		{
			name:        "Shopify Custom Access Token",
			pattern:     `shpca_[a-fA-F0-9]{32}`,
			severity:    SeverityCritical,
			description: "Shopify Custom Access Token",
		},
		{
			name:        "Shopify Private App Token",
			pattern:     `shppa_[a-fA-F0-9]{32}`,
			severity:    SeverityCritical,
			description: "Shopify Private App Access Token",
		},
		{
			name:        "Shopify Shared Secret",
			pattern:     `shpss_[A-Za-z0-9]{32}`,
			severity:    SeverityHigh,
			description: "Shopify Shared Secret",
		},
		{
			name:        "NPM Token",
			pattern:     `\b(npm_[a-zA-Z0-9]{36})(?:[\x60'"\s;]|\\[nr]|$)`,
			severity:    SeverityHigh,
			description: "NPM Access Token",
		},
		{
			name:        "PyPI API Token",
			pattern:     `pypi-AgEIcHlwaS5vcmc[\w-]{50,1000}`,
			severity:    SeverityHigh,
			description: "PyPI API Token",
		},
		{
			name:        "Airtable Personal Access Token",
			pattern:     `\b(pat[a-zA-Z0-9]{14}\.[a-f0-9]{64})\b`,
			severity:    SeverityHigh,
			description: "Airtable Personal Access Token",
		},
		{
			name:        "Cloudinary API Key",
			pattern:     `cloudinary://[0-9]{15}:[A-Za-z0-9_\-]+@[a-z0-9]+`,
			severity:    SeverityHigh,
			description: "Cloudinary Credentials URL",
		},
		{
			name:        "Sentry DSN",
			pattern:     `https://[a-f0-9]{32}@[a-z0-9]+\.ingest\.sentry\.io/[0-9]+`,
			severity:    SeverityMedium,
			description: "Sentry DSN (Data Source Name)",
		},
		{
			name:        "Sentry Auth Token",
			pattern:     `(?i)[\w.-]{0,50}?(?:sentry)(?:[ \t\w.-]{0,20})[\s'"]{0,3}(?:=|>|:{1,3}=|\|\||:|=>|\?=|,)[\x60'"\s=]{0,5}([a-f0-9]{64})(?:[\x60'"\s;]|\\[nr]|$)`,
			severity:    SeverityHigh,
			description: "Sentry Auth Token",
		},
		{
			name:        "Algolia API Key",
			pattern:     `(?i)[\w.-]{0,50}?(?:algolia)(?:[ \t\w.-]{0,20})[\s'"]{0,3}(?:=|>|:{1,3}=|\|\||:|=>|\?=|,)[\x60'"\s=]{0,5}([a-z0-9]{32})(?:[\x60'"\s;]|\\[nr]|$)`,
			severity:    SeverityHigh,
			description: "Algolia API Key",
		},
		{
			name:        "Bugsnag API Key",
			pattern:     `(?i)bugsnag.{0,20}[=:]\s*['"]?([a-f0-9]{32})['"]?`,
			severity:    SeverityMedium,
			description: "Bugsnag API Key",
		},
		{
			name:        "New Relic License Key",
			pattern:     `NRAK-[A-Z0-9]{27}`,
			severity:    SeverityHigh,
			description: "New Relic License Key",
		},
		{
			name:        "New Relic Insert Key",
			pattern:     `NRII-[A-Za-z0-9\-_]{32}`,
			severity:    SeverityHigh,
			description: "New Relic Insert Key",
		},
		{
			name:        "New Relic Browser API Token",
			pattern:     `NRJS-[a-f0-9]{19}`,
			severity:    SeverityHigh,
			description: "New Relic Browser API Token",
		},
		{
			// More precise Mapbox token format: pk.<60 chars>.<22 chars>
			name:        "Mapbox Public Token",
			pattern:     `(?i)[\w.-]{0,50}?(?:mapbox)(?:[ \t\w.-]{0,20})[\s'"]{0,3}(?:=|>|:{1,3}=|\|\||:|=>|\?=|,)[\x60'"\s=]{0,5}(pk\.[a-zA-Z0-9_\-]{60}\.[a-zA-Z0-9_\-]{22})(?:[\x60'"\s;]|\\[nr]|$)`,
			severity:    SeverityMedium,
			description: "Mapbox Public API Token",
		},
		{
			name:        "Mapbox Secret Token",
			pattern:     `sk\.eyJ1IjoiW[A-Za-z0-9\-_]+`,
			severity:    SeverityHigh,
			description: "Mapbox Secret API Token",
		},
		{
			name:        "Zendesk Secret Key",
			pattern:     `(?i)[\w.-]{0,50}?(?:zendesk)(?:[ \t\w.-]{0,20})[\s'"]{0,3}(?:=|>|:{1,3}=|\|\||:|=>|\?=|,)[\x60'"\s=]{0,5}([a-zA-Z0-9]{40,})(?:[\x60'"\s;]|\\[nr]|$)`,
			severity:    SeverityHigh,
			description: "Zendesk API Token",
		},
		{
			name:        "PagerDuty Integration Key",
			pattern:     `(?i)pagerduty.{0,20}[=:]\s*['"]?([A-Za-z0-9+/]{32})['"]?`,
			severity:    SeverityHigh,
			description: "PagerDuty Integration Key",
		},
		{
			name:        "Notion API Token",
			pattern:     `\b(ntn_[0-9]{11}[A-Za-z0-9]{35})(?:[\x60'"\s;]|\\[nr]|$)`,
			severity:    SeverityHigh,
			description: "Notion API Token",
		},
		{
			name:        "Linear API Key",
			pattern:     `lin_api_(?i)[a-z0-9]{40}`,
			severity:    SeverityHigh,
			description: "Linear API Key",
		},
		{
			name:        "Grafana API Key",
			pattern:     `\b(eyJrIjoi[A-Za-z0-9]{70,400}={0,3})(?:[\x60'"\s;]|\\[nr]|$)`,
			severity:    SeverityHigh,
			description: "Grafana API Key",
		},
		{
			name:        "Grafana Cloud API Token",
			pattern:     `\b(glc_[A-Za-z0-9+/]{32,400}={0,3})(?:[\x60'"\s;]|\\[nr]|$)`,
			severity:    SeverityHigh,
			description: "Grafana Cloud API Token",
		},
		{
			name:        "Grafana Service Account Token",
			pattern:     `\b(glsa_[A-Za-z0-9]{32}_[A-Fa-f0-9]{8})(?:[\x60'"\s;]|\\[nr]|$)`,
			severity:    SeverityHigh,
			description: "Grafana Service Account Token",
		},
		{
			name:        "Doppler API Token",
			pattern:     `dp\.pt\.(?i)[a-z0-9]{43}`,
			severity:    SeverityHigh,
			description: "Doppler API Token",
		},
		{
			name:        "Fly.io Access Token",
			pattern:     `\b(fo1_[\w-]{43}|fm1[ar]_[a-zA-Z0-9+\/]{100,}={0,3})(?:[\x60'"\s;]|\\[nr]|$)`,
			severity:    SeverityHigh,
			description: "Fly.io Access Token",
		},
		{
			name:        "Dropbox API Token",
			pattern:     `(?i)[\w.-]{0,50}?(?:dropbox)(?:[ \t\w.-]{0,20})[\s'"]{0,3}(?:=|>|:{1,3}=|\|\||:|=>|\?=|,)[\x60'"\s=]{0,5}([a-z0-9]{11}(AAAAAAAAAA)[a-z0-9\-_=]{43}|sl\.[a-z0-9\-=_]{135})(?:[\x60'"\s;]|\\[nr]|$)`,
			severity:    SeverityHigh,
			description: "Dropbox API Access Token",
		},
		{
			name:        "HubSpot API Key",
			pattern:     `(?i)[\w.-]{0,50}?(?:hubspot)(?:[ \t\w.-]{0,20})[\s'"]{0,3}(?:=|>|:{1,3}=|\|\||:|=>|\?=|,)[\x60'"\s=]{0,5}([0-9A-F]{8}-[0-9A-F]{4}-[0-9A-F]{4}-[0-9A-F]{4}-[0-9A-F]{12})(?:[\x60'"\s;]|\\[nr]|$)`,
			severity:    SeverityHigh,
			description: "HubSpot API Key",
		},
		{
			name:        "Dynatrace API Token",
			pattern:     `dt0c01\.(?i)[a-z0-9]{24}\.[a-z0-9]{64}`,
			severity:    SeverityHigh,
			description: "Dynatrace API Token",
		},
		{
			name:        "Datadog API Token",
			pattern:     `(?i)[\w.-]{0,50}?(?:datadog)(?:[ \t\w.-]{0,20})[\s'"]{0,3}(?:=|>|:{1,3}=|\|\||:|=>|\?=|,)[\x60'"\s=]{0,5}([a-z0-9]{40})(?:[\x60'"\s;]|\\[nr]|$)`,
			severity:    SeverityHigh,
			description: "Datadog API Token",
		},
		{
			name:        "Pulumi API Token",
			pattern:     `\b(pul-[a-f0-9]{40})(?:[\x60'"\s;]|\\[nr]|$)`,
			severity:    SeverityHigh,
			description: "Pulumi API Token",
		},
		{
			name:        "Postman API Token",
			pattern:     `\b(PMAK-[a-f0-9]{24}-[a-zA-Z0-9]{34})(?:[\x60'"\s;]|\\[nr]|$)`,
			severity:    SeverityHigh,
			description: "Postman API Token",
		},
		{
			name:        "Typeform API Token",
			pattern:     `\b(tfp_[a-z0-9\-_\.=]{59})(?:[\x60'"\s;]|\\[nr]|$)`,
			severity:    SeverityHigh,
			description: "Typeform API Token",
		},
		{
			name:        "Okta Access Token",
			pattern:     `(?i)[\w.-]{0,50}?(?:okta)(?:[ \t\w.-]{0,20})[\s'"]{0,3}(?:=|>|:{1,3}=|\|\||:|=>|\?=|,)[\x60'"\s=]{0,5}(00[\w=\-]{40})(?:[\x60'"\s;]|\\[nr]|$)`,
			severity:    SeverityHigh,
			description: "Okta Access Token",
		},
		{
			name:        "Alibaba Access Key ID",
			pattern:     `\b(LTAI(?i)[a-z0-9]{20})(?:[\x60'"\s;]|\\[nr]|$)`,
			severity:    SeverityCritical,
			description: "Alibaba Cloud Access Key ID",
		},

		// ─── Generic High-Entropy Secret Patterns ─────────────────────────────────────
		// All generic patterns use entropy gating to suppress FPs from minified JS
		{
			name:         "Generic API Key Assignment",
			pattern:      `(?i)(?:api[_-]?key|apikey|api[_-]?secret)\s*[=:]\s*['"]([A-Za-z0-9\-_]{20,64})['"]`,
			severity:     SeverityMedium,
			description:  "Generic API Key assignment",
			entropyCheck: true,
			minEntropy:   3.3,
		},
		{
			name:         "Generic Secret Assignment",
			pattern:      `(?i)(?:secret[_-]?key|client[_-]?secret)\s*[=:]\s*['"]([A-Za-z0-9\-_!@#$%^&*]{16,64})['"]`,
			severity:     SeverityMedium,
			description:  "Generic secret key assignment",
			entropyCheck: true,
			minEntropy:   3.3,
		},
		{
			name:         "Generic Password Assignment",
			pattern:      `(?i)(?:password|passwd|pwd)\s*[=:]\s*['"]([^'"]{8,64})['"]`,
			severity:     SeverityMedium,
			description:  "Hardcoded password",
			entropyCheck: true,
			minEntropy:   2.5,
		},
		{
			name:         "Generic Token Assignment",
			pattern:      `(?i)(?:auth[_-]?token|access[_-]?token)\s*[=:]\s*['"]([A-Za-z0-9\-_./+]{20,200})['"]`,
			severity:     SeverityMedium,
			description:  "Generic token assignment",
			entropyCheck: true,
			minEntropy:   3.5,
		},
	}

	for _, r := range raw {
		compiled, err := regexp.Compile(r.pattern)
		if err != nil {
			continue
		}
		p := &Pattern{
			Name:         r.name,
			Regex:        compiled,
			Severity:     r.severity,
			Description:  r.description,
			EntropyCheck: r.entropyCheck,
			MinEntropy:   r.minEntropy,
		}
		if r.context != "" {
			ctx, err := regexp.Compile(r.context)
			if err == nil {
				p.ContextRegex = ctx
			}
		}
		Patterns = append(Patterns, p)
	}
}
