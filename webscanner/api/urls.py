from django.urls import include, path
from rest_framework.routers import DefaultRouter
from . import views

router = DefaultRouter()
router.register(r'users', views.UserViewSet)
router.register(r'scans', views.ScanViewSet)
router.register(r'urls', views.Scan_UrlViewSet)
router.register(r'requests', views.RequestViewSet)
router.register(r'responses', views.ResponseViewSet)
router.register(r'vulnerabilities', views.VulnerabilityViewSet)

urlpatterns = [
    path('', include(router.urls)),
    path('api-auth/', include('rest_framework.urls', namespace='rest_framework'))
]