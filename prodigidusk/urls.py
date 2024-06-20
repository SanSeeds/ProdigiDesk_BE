"""
URL configuration for prodigidusk project.

The `urlpatterns` list routes URLs to views. For more information please see:
    https://docs.djangoproject.com/en/5.0/topics/http/urls/
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
from django.urls import path
from core import views

urlpatterns = [
    path('admin/', admin.site.urls),
    path('', views.landing, name='landing'),
    path('about/', views.about, name='about'),
    path('signin/', views.signin, name='signin'),
    path('forgot_password/', views.forgot_password, name='forgot_password'),
    path('reset_password/', views.reset_password, name='reset_password'),
    path('dashboard/', views.dashboard, name='dashboard'),
    path('email_generator/', views.email_generator, name='email_generator'),
    path('business_proposal_generator/', views.business_proposal_generator, name='business_proposal_generator'),
    path('offer_letter_generator/', views.offer_letter_generator, name='offer_letter_generator'),
    path('sales_script_generator/', views.sales_script_generator, name='sales_script_generator'),
    path('summarize_document/', views.summarize_document, name='summarize_document'),
    path('content_generator/', views.content_generator, name='content_generator'),
    path('generated_content/', views.generated_content, name='generated_content'),
    path('translate_content/', views.translate_content, name='translate_content'),
    path('logout/', views.logout_view, name='logout'),
    path('profile/', views.profile, name='profile'),
    path('translate/', views.translate, name='translate'),
    path('change_password/', views.change_password, name='change_password'),
]

