from django.contrib.auth.models import User
from rest_framework import serializers
from .models import Scan, Scan_Url, Request, Response, Vulnerability

# class UserSerializer(serializers.ModelSerializer):
#     class Meta:
#         model = User
#         fields = ['id', 'username', 'email', 'password', 'scans']


class Scan_UrlSerializer(serializers.ModelSerializer):
    class Meta:
        model = Scan_Url
        fields = '__all__'

class ScanSerializer(serializers.ModelSerializer):
    target_url = serializers.URLField(write_only=True)
    end_time = serializers.DateTimeField(allow_null=True)

    class Meta:
        model = Scan
        fields = '__all__'

class RequestSerializer(serializers.ModelSerializer):
    class Meta:
        model = Request
        fields = '__all__'

class ResponseSerializer(serializers.ModelSerializer):
    class Meta:
        model = Response
        fields = '__all__'

class VulnerabilitySerializer(serializers.ModelSerializer):
    cvss = serializers.FloatField(allow_null=True)
    cve = serializers.CharField(allow_null=True)
    recommendation = serializers.CharField(allow_null=True)
    proof_of_concept = serializers.CharField(allow_null = True)

    class Meta:
        model = Vulnerability
        fields = '__all__'

class Scan_UrlWithVulnerabilitiesSerializer(serializers.ModelSerializer):
    vulnerabilities = VulnerabilitySerializer(many=True, read_only=True, source='vulnerability_set')

    class Meta:
        model = Scan_Url
        fields = ['id', 'url', 'vulnerabilities']
