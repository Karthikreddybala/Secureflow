"""
URL configuration for ml_model project.

The `urlpatterns` list routes URLs to views. For more information please see:
    https://docs.djangoproject.com/en/5.2/topics/http/urls/
Examples:
Function views
    1. Add an import:  from my_app import views
    2. Add a URL to urlpatterns:  path('', views.home, name='home')
Class-based views
    1. Add an import:  from other_app.views import Home
    2. Add a URL to urlpatterns:  path('', Home.as_view(), name='home')
Including another URLconf
    1. Import the include() function: from django.urls import include, path
    2. Add a URL to urlpatterns:  path('blog/', include('blog.urls'))
"""
from django.contrib import admin
from django.urls import path, include

urlpatterns = [
    path("model_app/", include("model_app.urls")),
]


# ------------------------------------ruls
def rule_engine(flow):
    score = 0
    attack_type = "Unknown"

    # DDoS detection
    if flow["Flow_Pkts_s"] > 3000:
        score += 20
        attack_type = "DDoS"

    # Port Scan detection
    if flow["Tot_Fwd_Pkts"] > 100 and flow["Pkt_Size_Variance"] < 5:
        score += 15
        attack_type = "PortScan"

    # Brute Force detection
    if flow["Fwd_IAT_Mean"] < 200:
        score += 10
        attack_type = "BruteForce"

    # Web attack detection
    if flow["Flow_Byts_s"] > 150000 and flow["SYN_Flag"] == 1:
        score += 25
        attack_type = "WebAttack"

    return score, attack_type