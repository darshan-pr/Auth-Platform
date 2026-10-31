output "app_url" {
  value = local.app_url
}

output "alb_dns_name" {
  description = "Create a CNAME for var.domain_name pointing here."
  value       = aws_lb.app.dns_name
}

output "acm_validation_records" {
  description = "Add these CNAME records at your DNS provider so ACM can issue the certificate."
  value = [
    for o in aws_acm_certificate.app.domain_validation_options : {
      name  = o.resource_record_name
      type  = o.resource_record_type
      value = o.resource_record_value
    }
  ]
}

output "instance_id" {
  value = aws_instance.app.id
}

output "ssm_prefix" {
  value = local.ssm_prefix
}

output "rds_endpoint" {
  value = aws_db_instance.main.address
}

output "memorydb_endpoint" {
  value = aws_memorydb_cluster.main.cluster_endpoint[0].address
}
