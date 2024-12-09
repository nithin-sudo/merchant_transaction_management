from django.urls import path
from . import views
from .views import OrderListView
from .views import RefundsListView
from .views import UserListView
from .views import users
from .views import update_merchant_status
from .views import stripe_checkout
from .views import create_checkout_session

urlpatterns = [
    path('login/', views.login_view, name='login'),
    path('dashboard/', views.dashboard, name='dashboard'), # URL for dashboard page
    path('create-user/', views.create_user, name='create_user'),
    path('orders/', views.orders, name='orders'),
    path('refunds/', views.refunds, name='refunds'),
    path('logout/', views.logout_view, name='logout'),
    path('orders_data/', OrderListView.as_view(), name='orders_data'),  # URL for DataTables AJAX
    path('orders/get_order/<int:order_id>/', views.get_order, name='get_order'),
    path('orders/<int:order_id>/update/', views.update_order, name='update_order'),
    path('orders/<int:order_id>/details/', views.get_order_details, name='order_details'),
    path('filter_orders/', views.filter_orders, name='filter_orders'),
    path('get_merchants/', views.get_merchants, name='get_merchants'),
    path('refunds-data/', RefundsListView.as_view(), name='refunds_data'),  # For DataTable AJAX
    path('create-merchant-user/', views.create_merchant_user, name='create_merchant_user'),
    path('users-data/', UserListView.as_view(), name='users_data'),
    path('users/', users, name='users'),
    path('update-merchant-status/<int:merchant_id>/', update_merchant_status, name='update_merchant_status'),
    path('delete-user/<int:user_id>/', views.delete_user, name='delete_user'),
    path('change-password/<int:user_id>/', views.change_password, name='change_password'),
    path('dashboard-metrics/', views.dashboard_metrics, name='dashboard_metrics'),
    path('last-7-days-chart/', views.last_7_days_chart, name='last_7_days_chart'),
    path('dummy-checkout/', views.dummy_checkout, name='dummy_checkout'),
    path("checkout/", stripe_checkout, name="stripe-checkout"),
    path("create-checkout-session/", create_checkout_session, name="create-checkout-session"),
    path('success/', views.success_view, name='success'),
    path('cancel/', views.cancel_view, name='cancel'),
    path('order-confirmation/<int:order_id>/', views.order_confirmation, name='order-confirmation'),
    path('', views.landing_page, name='landing_page'),
]




