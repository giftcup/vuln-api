from rest_framework import viewsets, status
from rest_framework.response import Response as Res
from rest_framework.decorators import action
from rest_framework.permissions import IsAuthenticated
from django.contrib.auth.models import User
from .models import Scan, Scan_Url, Request, Response, Vulnerability
from .serializers import UserSerializer, ScanSerializer, Scan_UrlSerializer, RequestSerializer, ResponseSerializer, VulnerabilitySerializer
from .services import ScanService, SecurityHeaderService, XSSService, SQLInjectionService

class UserViewSet(viewsets.ModelViewSet):
    queryset = User.objects.all()
    serializer_class = UserSerializer

class ScanViewSet(viewsets.ModelViewSet):
    queryset = Scan.objects.all()
    serializer_class = ScanSerializer
    permission_classes = [IsAuthenticated]

    def create(self, request, *args, **kwargs):
        serializer = self.get_serializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        target_url = serializer.validated_data['target_url']
        user = request.user

        # Create Scan and ScanURL
        scan, scan_url = ScanService.create_scan_with_url(user, target_url)

        #Scan for vulnerabilities
        security_header_vulnerabilities = SecurityHeaderService.scan_for_vulnerabilities(scan)
        xss_vulnerabilities = XSSService.scan_for_vulnerabilities(scan)
        sqli_vulnerabilities = SQLInjectionService.scan_for_vulnerabilities(scan)

        # vulnerabilities = security_header_vulnerabilities + xss_vulnerabilities + sqli_vulnerabilities

        # Serialize the created Scan and ScanURL instances
        scan_serializer = self.get_serializer(scan)
        scan_url_serializer = Scan_UrlSerializer(scan_url, context={'request': request})
        # vulnerability_serializer = VulnerabilitySerializer(vulnerabilities, many=True, context={'request': request})
        security_header_serializer = VulnerabilitySerializer(security_header_vulnerabilities, many=True, context={'request': request})
        xss_serializer = VulnerabilitySerializer(xss_vulnerabilities, many=True, context={'request': request})
        sqli_vulnerabilities = VulnerabilitySerializer(sqli_vulnerabilities, many=True, context={'request': request})


        return Res({
            'scan': scan_serializer.data,
            'scan_url': scan_url_serializer.data,
            'security_header_vulnerabilities': security_header_serializer.data,
            'xss_vulnerabilities': xss_serializer.data,
            'sqli_vulnerabilities': sqli_vulnerabilities.data
        }, status=status.HTTP_201_CREATED)

class Scan_UrlViewSet(viewsets.ModelViewSet):
    queryset = Scan_Url.objects.all()
    serializer_class = Scan_UrlSerializer

class RequestViewSet(viewsets.ModelViewSet):
    queryset = Request.objects.all()
    serializer_class = RequestSerializer

class ResponseViewSet(viewsets.ModelViewSet):
    queryset = Response.objects.all()
    serializer_class = ResponseSerializer

class VulnerabilityViewSet(viewsets.ModelViewSet):
    queryset = Vulnerability.objects.all()
    serializer_class = VulnerabilitySerializer
