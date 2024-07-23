from django.db import models
from django.contrib.auth.models import User

class Scan(models.Model):
    user = models.ForeignKey(User, on_delete=models.CASCADE)
    target_url = models.TextField()
    start_time = models.DateTimeField()
    end_time = models.DateTimeField(null=True)
    scanner_ip = models.CharField(max_length=45)

class Scan_Url(models.Model):
    scan = models.ForeignKey(Scan, on_delete=models.CASCADE)
    scan_url = models.TextField()
    status_code = models.IntegerField()
    headers = models.TextField()
    html_content = models.TextField()

class Request(models.Model):
    scan_url = models.ForeignKey(Scan_Url, on_delete=models.CASCADE)
    method = models.CharField(max_length=10)
    payload = models.TextField()
    headers = models.TextField()

class Response(models.Model):
    request = models.ForeignKey(Request, on_delete=models.CASCADE)
    status_code = models.IntegerField()
    headers = models.TextField()
    content = models.TextField()

class Vulnerability(models.Model):
    scan_url = models.ForeignKey(Scan_Url, on_delete=models.CASCADE)
    type = models.CharField(max_length=50)
    description = models.TextField()
    severity = models.CharField(max_length=10, choices=[('low', 'Low'), ('medium', 'Medium'), ('high', 'High')])
    recommendation = models.TextField(null=True)
    cvss = models.FloatField(null=True)
    cve = models.TextField(null=True)
    proof_of_concept = models.TextField(null=True)