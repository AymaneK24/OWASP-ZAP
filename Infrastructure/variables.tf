variable "resource_group_name" {
  description = "Resource group name for the AKS cluster of SonarQube"
  type        = string
  default     = "owaspzap-application"
}

variable "resource_group_location" {
  description = "Location of the resource group"
  type        = string
  default     = "eastus"
}

variable "aks_cluster_name" {
  description = "Name of the AKS cluster"
  type        = string
  default     = "owaspzap-aks"
}

variable "aks_dns_prefix" {
  description = "DNS prefix for AKS cluster"
  type        = string
  default     = "stage-dast"
}

variable "node_count" {
  description = "Number of AKS worker nodes"
  type        = number
  default     = 1
}