variable "availability_zones" {
  type        = string
  description = "to create in particular availability_zones"
}

variable "subnet_names" {
  type        = string
  description = "to create in particular subnet"
}

variable "instance_names" {
  type    = string
  default = "one"
}


variable "region" {
  description = "region which we are working"
  default     = "us-east-2"
}


