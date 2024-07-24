from django.urls import include, path
from rest_framework.routers import DefaultRouter
# from rest_framework.authtoken.views import obtain_auth_token
from . import views
from .views import ScanDetailView

router = DefaultRouter()
router.register(r'scans', views.ScanViewSet)
router.register(r'scan_urls', views.Scan_UrlViewSet)
router.register(r'requests', views.RequestViewSet)
router.register(r'responses', views.ResponseViewSet)
router.register(r'vulnerabilities', views.VulnerabilityViewSet)

urlpatterns = [
    path('', include(router.urls)),
    path('scans/<int:pk>/details/', views.ScanViewSet.as_view({'get': 'details'}), name='scan-details'),
    path('scans/all_scan_details/', views.ScanViewSet.as_view({'get': 'all_scan_details'}), name='all-scan-details'),
]