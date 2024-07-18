from django.contrib.auth.models import User
from rest_framework import serializers
from .models import Scan, Scan_Url, Request, Response, Vulnerability

class UserSerializer(serializers.HyperlinkedModelSerializer):
    scans = serializers.HyperlinkedRelatedField(
        many=True,
        view_name='scan-detail',
        read_only=True
    )

    class Meta:
        model = User
        fields = ['url', 'id', 'username', 'email', 'password', 'scans']


class Scan_UrlSerializer(serializers.HyperlinkedModelSerializer):
    scan = serializers.HyperlinkedRelatedField(
        view_name='scan-detail',
        read_only=True
    )

    requests = serializers.HyperlinkedRelatedField(
        many=True,
        view_name='request-detail',
        read_only=True
    )

    vulnerabilities = serializers.HyperlinkedRelatedField(
        many=True,
        view_name='vulnerability-detail',
        read_only=True
    )

    class Meta:
        model = Scan_Url
        fields = ['url', 'id', 'scan', 'scan_url', 'status_code', 'headers', 'html_content', 'requests', 'vulnerabilities']

class ScanSerializer(serializers.HyperlinkedModelSerializer):
    user = serializers.HyperlinkedRelatedField(
        view_name='user-detail',
        read_only=True
    )
    scan_urls = serializers.HyperlinkedRelatedField(
        many=True,
        view_name='scan_url-detail',
        read_only=True
    )
    target_url = serializers.URLField(write_only=True)

    end_time = serializers.DateTimeField(allow_null=True)

    class Meta:
        model = Scan
        fields = ['url', 'id', 'start_time', 'end_time', 'scanner_ip', 'user', 'scan_urls', 'target_url']

class RequestSerializer(serializers.HyperlinkedModelSerializer):
    scan_url = serializers.HyperlinkedRelatedField(
        view_name='scan_url-detail',
        read_only=True
    )
    response = serializers.HyperlinkedRelatedField(
        view_name='response-detail',
        read_only=True
    )

    class Meta:
        model = Request
        fields = ['url', 'id', 'scan_url', 'method', 'payload', 'headers', 'response']

class ResponseSerializer(serializers.HyperlinkedModelSerializer):
    request = serializers.HyperlinkedRelatedField(
        view_name='request-detail',
        read_only=True
    )
    class Meta:
        model = Response
        fields = ['url', 'id', 'request', 'status_code', 'headers', 'content']

class VulnerabilitySerializer(serializers.HyperlinkedModelSerializer):
    scan_url = serializers.HyperlinkedRelatedField(
        view_name='scan_url-detail',
        read_only=True
    )

    cvss = serializers.FloatField(allow_null=True)
    cve = serializers.CharField(allow_null=True)

    class Meta:
        model = Vulnerability
        fields = ['url', 'id', 'scan_url', 'type', 'description', 'severity', 'cvss', 'cve', 'proof_of_concept']
