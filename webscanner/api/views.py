from rest_framework import viewsets, status, generics
from rest_framework.response import Response as Res
from rest_framework.decorators import action, api_view
from rest_framework.permissions import IsAuthenticated, AllowAny
from django.contrib.auth.models import User
from django.shortcuts import get_object_or_404
from .models import Scan, Scan_Url, Request as RequestModel, Response, Vulnerability
from .serializers import ScanSerializer, Scan_UrlSerializer, RequestSerializer, ResponseSerializer, VulnerabilitySerializer, Scan_UrlWithVulnerabilitiesSerializer
from .services import ScanService, SecurityHeaderService, XSSService, SQLInjectionService, CSRFService

# class UserViewSet(viewsets.ModelViewSet):
#     queryset = User.objects.all()
#     serializer_class = UserSerializer

class ScanViewSet(viewsets.ModelViewSet):
    queryset = Scan.objects.all()
    serializer_class = ScanSerializer
    lookup_field = 'id'

    def create(self, request, *args, **kwargs):
        serializer = self.get_serializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        target_url = serializer.validated_data['target_url']

        # Create Scan and Scan_Url
        scan, scan_urls = ScanService.create_scan_with_urls(target_url)

        #Scan for vulnerabilities
        security_header_vulnerabilities = SecurityHeaderService.scan_for_vulnerabilities(scan)
        xss_vulnerabilities = XSSService.scan_for_vulnerabilities(scan)
        sqli_vulnerabilities = SQLInjectionService.scan_for_vulnerabilities(scan)
        csrf_vulnerabilities = CSRFService.scan_for_vulnerabilities(scan)

        # Serialize the created Scan and Scan_Url instances
        scan_serializer = self.get_serializer(scan)
        scan_url_serializer = Scan_UrlSerializer(scan_urls, many=True, context={'request': request})
        security_header_serializer = VulnerabilitySerializer (security_header_vulnerabilities, many=True, context={'request': request})
        xss_serializer = VulnerabilitySerializer(xss_vulnerabilities, many=True, context={'request': request})
        sqli_vulnerabilities = VulnerabilitySerializer(sqli_vulnerabilities, many=True, context={'request': request})
        csrf_vulnerabilities = VulnerabilitySerializer(csrf_vulnerabilities, many=True, context={'request': request})


        return Res({
            'scan': scan_serializer.data,
            'scan_url': scan_url_serializer.data,
            'security_header_vulnerabilities': security_header_serializer.data,
            'xss_vulnerabilities': xss_serializer.data,
            'sqli_vulnerabilities': sqli_vulnerabilities.data,
            'csrf_vulnerabilities': csrf_vulnerabilities.data
        }, status=status.HTTP_201_CREATED)
    
    @action(detail=True, methods=['get'])
    def details(self, request, id=None):
        try:
            scan = self.get_object()
        except Scan.DoesNotExist:
            return Response({'error': 'Scan not found'}, status=status.HTTP_404_NOT_FOUND)

        scan_urls = Scan_Url.objects.filter(scan=scan)
        scan_urls_data = Scan_UrlWithVulnerabilitiesSerializer(scan_urls, many=True, context={'request': request}).data

        total_sites_scanned = scan_urls.count()
        total_vulnerabilities = Vulnerability.objects.filter(scan_url__in=scan_urls).count()

        response_data = {
            'scan': scan.id,
            'total_sites_scanned': total_sites_scanned,
            'total_vulnerabilities': total_vulnerabilities,
            'scan_urls': scan_urls_data
        }

        return Res(response_data, status=status.HTTP_200_OK)
    
    
    @action(detail=False, methods=['get'])
    def all_scan_details(self, request):
        scans = Scan.objects.all()
        total_scans = scans.count()
        total_vulnerabilities = Vulnerability.objects.count()

        scan_details = []
        for scan in scans:
            vulnerabilities = Vulnerability.objects.filter(scan_url__scan=scan)
            high_vulnerabilities = vulnerabilities.filter(severity='high').count()
            medium_vulnerabilities = vulnerabilities.filter(severity='medium').count()
            low_vulnerabilities = vulnerabilities.filter(severity='low').count()

            scan_data = {
                'id': scan.id,
                'target_url': scan.target_url,
                'date_performed': scan.start_time.date(),
                'high_vulnerabilities': high_vulnerabilities,
                'medium_vulnerabilities': medium_vulnerabilities,
                'low_vulnerabilities': low_vulnerabilities,
            }
            scan_details.append(scan_data)

        response_data = {
            'total_scans': total_scans,
            'total_vulnerabilities': total_vulnerabilities,
            'scan_details': scan_details
        }

        return Res(response_data, status=status.HTTP_200_OK)
    

class ScanDetailView(generics.RetrieveAPIView):
    queryset = Scan.objects.all()
    serializer_class = ScanSerializer
    lookup_field = 'id'

class Scan_UrlViewSet(viewsets.ModelViewSet):
    queryset = Scan_Url.objects.all()
    serializer_class = Scan_UrlSerializer

class RequestViewSet(viewsets.ModelViewSet):
    queryset = RequestModel.objects.all()
    serializer_class = RequestSerializer

class ResponseViewSet(viewsets.ModelViewSet):
    queryset = Response.objects.all()
    serializer_class = ResponseSerializer

class VulnerabilityViewSet(viewsets.ModelViewSet):
    queryset = Vulnerability.objects.all()
    serializer_class = VulnerabilitySerializer
