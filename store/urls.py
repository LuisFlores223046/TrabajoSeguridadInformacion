from django.urls import path
from . import views

auth_urlpatterns = [
    path('login/', views.login_view, name='login'),
    path('register/', views.register_view, name='register'),
    path('logout/', views.logout_view, name='logout'),
]

customer_urlpatterns = [
    path('', views.store, name='store'),
    path('cart/', views.cart, name='cart'),
    path('checkout/', views.checkout, name='checkout'),
    path('product/<int:pk>/', views.customer_product_detail, name='customer_product_detail'),
    path('category/<int:pk>/', views.customer_category_detail, name='customer_category_detail'),
]

admin_urlpatterns = [
    path('admin-dashboard/', views.dashboard, name='dashboard'),

    path('admin-dashboard/products/', views.product_list, name='product_list'),
    path('admin-dashboard/products/new/', views.product_create, name='product_create'),
    path('admin-dashboard/products/<int:pk>/', views.product_detail, name='product_detail'),
    path('admin-dashboard/products/<int:pk>/edit/', views.product_update, name='product_update'),
    path('admin-dashboard/products/<int:pk>/delete/', views.product_delete, name='product_delete'),

    path('admin-dashboard/categories/', views.category_list, name='category_list'),
    path('admin-dashboard/categories/new/', views.category_create, name='category_create'),
    path('admin-dashboard/categories/<int:pk>/', views.category_detail, name='category_detail'),
    path('admin-dashboard/categories/<int:pk>/edit/', views.category_update, name='category_update'),
    path('admin-dashboard/categories/<int:pk>/delete/', views.category_delete, name='category_delete'),

    path('admin-dashboard/users/', views.user_list, name='user_list'),
]

order_urlpatterns = [
    path('admin-dashboard/orders/', views.order_list, name='order_list'),
    path('admin-dashboard/orders/<int:pk>/', views.order_detail, name='order_detail'),
    path('admin-dashboard/orders/<int:pk>/edit/', views.order_update, name='order_update'),
    path('admin-dashboard/orders/<int:pk>/delete/', views.order_delete, name='order_delete'),

    path('admin-dashboard/orders/<int:pk>/add-item/', views.add_order_item, name='add_order_item'),
    path('admin-dashboard/order-items/<int:pk>/edit/', views.edit_order_item, name='edit_order_item'),
    path('admin-dashboard/order-items/<int:pk>/delete/', views.delete_order_item, name='delete_order_item'),
]

cart_urlpatterns = [
    path('add-to-cart/<int:product_id>/', views.add_to_cart, name='add_to_cart'),
    path('update-cart/<int:product_id>/<str:action>/', views.update_cart, name='update_cart'),
    path('remove-from-cart/<int:product_id>/', views.remove_from_cart, name='remove_from_cart'),
]

account_urlpatterns = [
    path('my-account/', views.my_account, name='my_account'),
    path('my-orders/', views.my_orders, name='my_orders'),
    path('my-orders/<int:pk>/', views.order_customer_detail, name='order_customer_detail'),
]

urlpatterns = (
    auth_urlpatterns +
    customer_urlpatterns +
    admin_urlpatterns +
    order_urlpatterns +
    cart_urlpatterns +
    account_urlpatterns
)
