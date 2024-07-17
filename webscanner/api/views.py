from rest_framework import viewsets
# from rest_framework.decorators import action
# from rest_framework.Response import Response
from django.contrib.auth.models import User
from .models import Scan, Scan_Url, Request, Response, Vulnerability
from .serializers import UserSerializer, ScanSerializer, Scan_UrlSerializer, RequestSerializer, ResponseSerializer, VulnerabilitySerializer

class UserViewSet(viewsets.ModelViewSet):
    queryset = User.objects.all()
    serializer_class = UserSerializer

class ScanViewSet(viewsets.ModelViewSet):
    queryset = Scan.objects.all()
    serializer_class = ScanSerializer

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
