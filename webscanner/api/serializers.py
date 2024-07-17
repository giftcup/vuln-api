from django.contrib.auth.models import User
from rest_framework import serializers
from .models import Scan, Scan_Url, Request, Response, Vulnerability

class UserSerializer(serializers.HyperlinkedModelSerializer):
    class Meta:
        model = User
        fields = ['url', 'id', 'username', 'email', 'password']

class ScanSerializer(serializers.HyperlinkedModelSerializer):
    urls = serializers.HyperlinkedRelatedField(many=True, read_only=True, view_name='url-detail')

    class Meta:
        model = Scan
        fields = ['url', 'id', 'user', 'target_url', 'start_time', 'end_time', 'scanner_ip', 'urls']

class Scan_UrlSerializer(serializers.HyperlinkedModelSerializer):
    requests = serializers.HyperlinkedRelatedField(many=True, read_only=True, view_name='request-detail')
    vulnerabilities = serializers.HyperlinkedRelatedField(many=True, read_only=True, view_name="vulnerabilities")

    class Meta:
        model = Scan_Url
        fields = ['url', 'id', 'scan', 'scan_url', 'status_code', 'headers', 'html_content', 'requests', 'vulnerabilities']

class RequestSerializer(serializers.HyperlinkedModelSerializer):
    responses = serializers.HyperlinkedRelatedField(many=True, read_only=True, view_name='response-detail')

    class Meta:
        model = Request
        fields = ['url', 'id', 'scan_url', 'method', 'payload', 'headers', 'responses']

class ResponseSerializer(serializers.HyperlinkedModelSerializer):
    class Meta:
        model = Response
        fields = ['url', 'id', 'request', 'status_code', 'headers', 'content']

class VulnerabilitySerializer(serializers.HyperlinkedModelSerializer):
    cvss = serializers.FloatField(allow_null=True)
    cve = serializers.CharField(allow_null=True)

    class Meta:
        model = Vulnerability
        fields = ['url', 'id', 'scan_url', 'type', 'description', 'severity', 'cvss', 'cve', 'proof_of_concept']
