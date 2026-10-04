variable "region" {
  type        = string
  description = "AWS deployment region"
  default     = "eu-west-2"
}

variable "name_prefix" {
  type        = string
  description = "Prefix for created security resources"
  default     = "demo-sec-auto"
}

variable "alert_webhook_url" {
  type        = string
  description = "Optional Slack/Discord webhook URL for incident notifications"
  default     = ""
  sensitive   = true
}
