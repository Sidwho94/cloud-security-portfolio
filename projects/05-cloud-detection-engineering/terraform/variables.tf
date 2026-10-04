variable "region" {
  type        = string
  description = "AWS region for detection workgroup"
  default     = "eu-west-2"
}

variable "name_prefix" {
  type        = string
  description = "Prefix for security hunting resources"
  default     = "sec-hunting"
}
