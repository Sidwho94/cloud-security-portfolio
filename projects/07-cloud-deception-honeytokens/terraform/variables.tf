variable "region" {
  type        = string
  description = "AWS Region for deception infrastructure"
  default     = "eu-west-2"
}

variable "name_prefix" {
  type        = string
  description = "Prefix for canary resources"
  default     = "canary-sec"
}

variable "alert_webhook_url" {
  type        = string
  description = "Slack/Discord/Teams webhook URL for deception alerts"
  default     = ""
  sensitive   = true
}
